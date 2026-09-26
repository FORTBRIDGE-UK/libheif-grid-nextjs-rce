from __future__ import annotations

import hashlib
import io
from pathlib import Path
import struct
import unittest

from PIL import Image

from heap_calibrator import analyze_heap_calibration, resolve_heap_selector
from stack_profile import load_profile


LIBVIPS_BASE = 0x0000700000000000
ARENA_BASE = 0x0000710000000000
PIE_MANIFEST = (
    Path(__file__).resolve().parents[1]
    / "profiles/native_stack_profiles_pie.json"
)


def response_with_records(
    *anchors: int,
    related_delta: int = 0x68F30,
    first_position: int = 0x2000,
) -> bytes:
    profile = load_profile()
    calibration = profile.heap_calibration
    alpha = bytearray(128 * 8192)
    for index, anchor in enumerate(anchors):
        position = first_position + index * 0x1000

        def put(relative_qword: int, value: int) -> None:
            struct.pack_into("<Q", alpha, position + relative_qword * 8, value)

        arena = anchor & ~(calibration.arena_alignment - 1)
        peer = anchor + calibration.anchor_peer_delta
        put(-6, calibration.record_chunk_size_and_flags)
        put(-5, anchor + related_delta)
        put(-4, arena + calibration.arena_sentinel_offset)
        put(-3, 0)
        put(-2, 0)
        put(-1, peer)
        put(0, anchor)
        put(1, peer)
        put(2, LIBVIPS_BASE + calibration.libvips_record_offsets[0])
        put(3, LIBVIPS_BASE + calibration.libvips_record_offsets[1])
        put(4, calibration.record_marker)
        put(5, 0)
        put(6, LIBVIPS_BASE + calibration.libvips_record_offsets[2])
    channel = Image.frombytes("L", (128, 8192), bytes(alpha))
    zero = Image.new("L", channel.size, 0)
    image = Image.merge("RGBA", (zero, zero, zero, channel))
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def pie_response_with_records(
    *anchors: int,
    first_position: int = 0xEC000,
    prefix_override: tuple[int, ...] | None = None,
) -> bytes:
    profile = load_profile(manifest_path=PIE_MANIFEST)
    calibration = profile.heap_calibration
    alpha = bytearray(128 * 8192)
    prefix = prefix_override or calibration.record_prefix_qwords
    for index, anchor in enumerate(anchors):
        position = first_position + index * 0x800

        def put(relative_qword: int, value: int) -> None:
            struct.pack_into("<Q", alpha, position + relative_qword * 8, value)

        for prefix_index, value in enumerate(prefix):
            put(-9 + prefix_index, value)
        put(-3, anchor)
        put(-2, anchor + 0x2A0)
        put(-1, anchor + calibration.anchor_peer_delta)
        put(0, LIBVIPS_BASE + calibration.libvips_record_offsets[0])
        put(1, LIBVIPS_BASE + calibration.libvips_record_offsets[1])
        put(2, 0x12345678)
        put(3, 0)
        put(4, LIBVIPS_BASE + calibration.libvips_record_offsets[2])
    channel = Image.frombytes("L", (128, 8192), bytes(alpha))
    zero = Image.new("L", channel.size, 0)
    image = Image.merge("RGBA", (zero, zero, zero, channel))
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


class HeapCalibratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_profile()
        self.anchor = ARENA_BASE + 0x4F6E30

    def analyze(self, *anchors: int) -> dict[str, object]:
        return analyze_heap_calibration(
            response_with_records(*anchors),
            self.profile,
            LIBVIPS_BASE,
        )

    def test_complete_record_produces_ranked_candidate(self) -> None:
        result = self.analyze(self.anchor)
        self.assertEqual(result["status"], "candidates")
        self.assertEqual(result["candidate_selectors"], ["0x5970"])
        self.assertEqual(result["matches"][0]["anchor"], hex(self.anchor))

    def test_lowest_structural_anchor_is_selected_by_profile_rank(self) -> None:
        result = self.analyze(self.anchor + 0x5BC0, self.anchor)
        self.assertEqual(result["match_count"], 2)
        self.assertEqual(result["candidate_selectors"], ["0x5970"])

    def test_two_matching_responses_resolve_selector(self) -> None:
        observations = [self.analyze(self.anchor), self.analyze(self.anchor)]
        self.assertEqual(
            resolve_heap_selector(observations, self.profile),
            0x5970,
        )

    def test_one_multi_anchor_record_resolves_selector(self) -> None:
        self.assertEqual(
            resolve_heap_selector([self.analyze(self.anchor)], self.profile),
            0x5970,
        )

    def test_missing_record_produces_no_candidate(self) -> None:
        result = self.analyze()
        self.assertEqual(result["status"], "no_match")
        self.assertEqual(result["candidate_selectors"], [])

    def test_mismatched_libvips_base_produces_no_candidate(self) -> None:
        result = analyze_heap_calibration(
            response_with_records(self.anchor),
            self.profile,
            LIBVIPS_BASE + 0x1000,
        )
        self.assertEqual(result["candidate_selectors"], [])

    def test_out_of_range_related_pointer_produces_no_candidate(self) -> None:
        result = analyze_heap_calibration(
            response_with_records(self.anchor, related_delta=0x1000),
            self.profile,
            LIBVIPS_BASE,
        )
        self.assertEqual(result["candidate_selectors"], [])

    def test_record_at_last_complete_qword_is_scanned(self) -> None:
        last_complete_position = 128 * 8192 - 7 * 8
        result = analyze_heap_calibration(
            response_with_records(
                self.anchor,
                first_position=last_complete_position,
            ),
            self.profile,
            LIBVIPS_BASE,
        )
        self.assertEqual(result["candidate_selectors"], ["0x5970"])

    def test_two_repeated_selectors_are_rejected_as_ambiguous(self) -> None:
        other = self.anchor + 0x1000
        observations = [
            self.analyze(self.anchor),
            self.analyze(other),
            self.analyze(self.anchor),
            self.analyze(other),
        ]
        with self.assertRaisesRegex(ValueError, "ambiguous supported"):
            resolve_heap_selector(observations, self.profile)


class PieTailHeapCalibratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_profile(manifest_path=PIE_MANIFEST)
        self.anchor = ARENA_BASE + 0x4F6C30

    def analyze(self, *anchors: int, **kwargs: object) -> dict[str, object]:
        return analyze_heap_calibration(
            pie_response_with_records(*anchors, **kwargs),
            self.profile,
            LIBVIPS_BASE,
        )

    def test_tail_record_derives_current_lifetime_selector(self) -> None:
        image = pie_response_with_records(self.anchor)
        result = analyze_heap_calibration(image, self.profile, LIBVIPS_BASE)
        self.assertEqual(result["record_variant"], "pie_tail")
        self.assertEqual(result["candidate_selectors"], ["0x5970"])
        self.assertEqual(
            result["selector_source"],
            "profile_page_lane_and_returned_record",
        )
        self.assertEqual(result["response_sha256"], hashlib.sha256(image).hexdigest())
        self.assertEqual(result["matches"][0]["response_offset"], "0xec000")
        self.assertEqual(result["matches"][0]["anchor_page_low16"], "0x6000")

    def test_wrong_page_lane_is_not_accepted_as_record_evidence(self) -> None:
        result = self.analyze(ARENA_BASE + 0x4F7C30)
        self.assertEqual(result["match_count"], 0)
        self.assertEqual(result["record_candidate_selectors"], [])
        self.assertEqual(result["candidate_selectors"], ["0x5970"])
        self.assertEqual(result["selector_source"], "profile_page_lane")
        self.assertEqual(
            result["profile_selector_evidence"]["anchor_page_low16"],
            "0x6000",
        )

    def test_record_before_tail_scan_range_is_not_used(self) -> None:
        result = self.analyze(self.anchor, first_position=0xD0000)
        self.assertEqual(result["match_count"], 0)
        self.assertEqual(result["candidate_selectors"], ["0x5970"])

    def test_wrong_prefix_is_not_accepted_as_record_evidence(self) -> None:
        prefix = list(self.profile.heap_calibration.record_prefix_qwords)
        prefix[3] ^= 1
        result = self.analyze(self.anchor, prefix_override=tuple(prefix))
        self.assertEqual(result["match_count"], 0)
        self.assertEqual(result["record_candidate_selectors"], [])
        self.assertEqual(result["candidate_selectors"], ["0x5970"])

    def test_repeated_valid_records_produce_one_selector(self) -> None:
        result = self.analyze(self.anchor, self.anchor + 0x10000)
        self.assertEqual(result["match_count"], 2)
        self.assertEqual(result["candidate_selectors"], ["0x5970"])


if __name__ == "__main__":
    unittest.main()
