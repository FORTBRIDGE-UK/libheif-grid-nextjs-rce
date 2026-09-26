from __future__ import annotations

from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import random
import unittest

from PIL import Image

from profile_classifier import classify_libvips_profiles
from stack_profile import LeakAnchorProfile, LeakProfile, load_profile


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
SYNTHETIC_ALPHA_BYTES = 512


def alpha_response(
    placements: list[tuple[int, int]],
    *,
    alpha_bytes: int = SYNTHETIC_ALPHA_BYTES,
) -> bytes:
    if alpha_bytes % 64:
        raise ValueError("test alpha size must be divisible by 64")
    alpha = bytearray(alpha_bytes)
    for position, value in placements:
        alpha[position:position + 8] = value.to_bytes(8, "little")
    channel = Image.frombytes("L", (64, alpha_bytes // 64), bytes(alpha))
    zero = Image.new("L", channel.size, 0)
    image = Image.merge("RGBA", (zero, zero, zero, channel))
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


class ProfileClassifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.default = load_profile()
        leak = replace(
            self.default.libvips.leak,
            scan_end=SYNTHETIC_ALPHA_BYTES,
            supporting_hints={"os": "linux", "glibc": "2.42"},
        )
        self.current = replace(
            self.default,
            libvips=replace(self.default.libvips, leak=leak),
        )
        self.base = 0x0000700000000000
        self.immich = replace(
            self.default,
            profile_id="fixture-immich-v3.1.0-libvips-8.18.4",
            libvips=replace(
                self.default.libvips,
                version="8.18.4",
                filename="libvips.so.42.20.4",
                build_id="1fe26e1f68950305fcebf57a5458f78f4fe33051",
                sha256=(
                    "26e94cd91102943e989a748b396bcf091"
                    "b9c12f8439c119a971945a08f52a090"
                ),
                leak=LeakProfile(
                    anchors=(
                        LeakAnchorProfile(0x230CA0, 10),
                        LeakAnchorProfile(0x22B9D0, 1),
                    ),
                    required_anchors=2,
                    scan_start=0,
                    scan_end=262144,
                    scan_step=8,
                    pointer_min=0x0000500000000000,
                    pointer_max=0x0000800000000000,
                    base_alignment=0x1000,
                    supporting_hints={"os": "alpine", "framework": "immich"},
                ),
            ),
        )

    def current_response(self, base: int | None = None) -> bytes:
        selected_base = self.base if base is None else base
        return alpha_response([
            (index * 8, selected_base + anchor.offset)
            for index, anchor in enumerate(self.current.libvips.leak.anchors)
        ])

    def test_current_three_anchor_signature_selects_exact_profile(self) -> None:
        result = classify_libvips_profiles(self.current_response(), [self.current])
        self.assertEqual(result["status"], "selected")
        self.assertEqual(result["selected_profile_id"], self.current.profile_id)
        self.assertEqual(result["selected_base"], hex(self.base))
        self.assertEqual(len(result["selected_anchors"]), 3)

    def test_exact_libvips_8184_fixture_selects_only_its_profile(self) -> None:
        metadata = json.loads(
            (FIXTURES / "libvips-8.18.4-immich-response.json").read_text(),
        )
        response = (FIXTURES / metadata["fixture"]["filename"]).read_bytes()
        self.assertEqual(hashlib.sha256(response).hexdigest(), metadata["fixture"]["sha256"])
        current = replace(
            self.current,
            libvips=replace(
                self.current.libvips,
                leak=replace(self.current.libvips.leak, scan_end=262144),
            ),
        )
        result = classify_libvips_profiles(
            response,
            [current, self.immich],
            {"os": "alpine", "framework": "immich"},
        )
        self.assertEqual(result["status"], "selected")
        self.assertEqual(result["selected_profile_id"], self.immich.profile_id)
        self.assertEqual(result["selected_base"], metadata["expected_base"])
        self.assertEqual(
            [anchor["repetitions"] for anchor in result["selected_anchors"]],
            [17, 1],
        )
        current_result = next(
            candidate for candidate in result["candidates"]
            if candidate["profile_id"] == current.profile_id
        )
        self.assertEqual(current_result["status"], "rejected")

    def test_current_fixture_does_not_cross_match_second_build(self) -> None:
        immich = replace(
            self.immich,
            libvips=replace(
                self.immich.libvips,
                leak=replace(
                    self.immich.libvips.leak,
                    scan_end=SYNTHETIC_ALPHA_BYTES,
                ),
            ),
        )
        result = classify_libvips_profiles(
            self.current_response(), [self.current, immich],
        )
        self.assertEqual(result["selected_profile_id"], self.current.profile_id)
        second = next(
            candidate for candidate in result["candidates"]
            if candidate["profile_id"] == immich.profile_id
        )
        self.assertEqual(second["status"], "rejected")

    def test_missing_anchor_returns_no_match(self) -> None:
        anchors = self.current.libvips.leak.anchors[:-1]
        response = alpha_response([
            (index * 8, self.base + anchor.offset)
            for index, anchor in enumerate(anchors)
        ])
        result = classify_libvips_profiles(response, [self.current])
        self.assertEqual(result["status"], "no_match")
        self.assertIsNone(result["selected_profile_id"])

    def test_mismatched_anchor_bases_return_no_match(self) -> None:
        response = alpha_response([
            (index * 8, self.base + index * 0x1000 + anchor.offset)
            for index, anchor in enumerate(self.current.libvips.leak.anchors)
        ])
        result = classify_libvips_profiles(response, [self.current])
        self.assertEqual(result["status"], "no_match")

    def test_minimum_repetition_is_enforced(self) -> None:
        immich = replace(
            self.immich,
            libvips=replace(
                self.immich.libvips,
                leak=replace(
                    self.immich.libvips.leak,
                    scan_end=SYNTHETIC_ALPHA_BYTES,
                ),
            ),
        )
        response = alpha_response([
            (0, self.base + 0x230CA0),
            (8, self.base + 0x22B9D0),
        ])
        result = classify_libvips_profiles(response, [immich])
        self.assertEqual(result["status"], "no_match")

    def test_two_bases_in_one_profile_are_ambiguous(self) -> None:
        placements = []
        for base_index, base in enumerate((self.base, self.base + 0x100000)):
            placements.extend(
                ((base_index * 3 + anchor_index) * 8, base + anchor.offset)
                for anchor_index, anchor in enumerate(
                    self.current.libvips.leak.anchors,
                )
            )
        result = classify_libvips_profiles(alpha_response(placements), [self.current])
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(result["supported_pair_count"], 2)
        self.assertIsNone(result["selected_base"])

    def test_two_matching_profiles_are_ambiguous(self) -> None:
        duplicate = replace(self.current, profile_id="duplicate-profile")
        result = classify_libvips_profiles(
            self.current_response(), [self.current, duplicate],
        )
        self.assertEqual(result["status"], "ambiguous")
        self.assertEqual(result["supported_pair_count"], 2)

    def test_unknown_build_data_returns_no_match(self) -> None:
        response = alpha_response([
            (0, self.base + 0x111110),
            (8, self.base + 0x222220),
            (16, self.base + 0x333330),
        ])
        result = classify_libvips_profiles(response, [self.current])
        self.assertEqual(result["status"], "no_match")

    def test_out_of_window_anchors_are_ignored(self) -> None:
        leak = replace(self.current.libvips.leak, scan_end=64)
        profile = replace(
            self.current,
            libvips=replace(self.current.libvips, leak=leak),
        )
        response = alpha_response([
            (64 + index * 8, self.base + anchor.offset)
            for index, anchor in enumerate(leak.anchors)
        ])
        result = classify_libvips_profiles(response, [profile])
        self.assertEqual(result["status"], "no_match")

    def test_hints_alone_never_select_a_profile(self) -> None:
        result = classify_libvips_profiles(
            alpha_response([]),
            [self.current],
            {"os": "linux", "glibc": "2.42"},
        )
        self.assertEqual(result["status"], "no_match")
        matches = result["candidates"][0]["supporting_hints"]["matches"]
        self.assertEqual(matches, {"os": True, "glibc": True})

    def test_hints_do_not_resolve_two_matching_profiles(self) -> None:
        preferred = replace(
            self.current,
            profile_id="hint-preferred",
            libvips=replace(
                self.current.libvips,
                leak=replace(
                    self.current.libvips.leak,
                    supporting_hints={"os": "preferred-os"},
                ),
            ),
        )
        result = classify_libvips_profiles(
            self.current_response(),
            [self.current, preferred],
            {"os": "preferred-os"},
        )
        self.assertEqual(result["status"], "ambiguous")
        self.assertIsNone(result["selected_profile_id"])

    def test_short_response_rejects_candidate(self) -> None:
        short_profile = replace(
            self.current,
            libvips=replace(
                self.current.libvips,
                leak=replace(self.current.libvips.leak, scan_end=1024),
            ),
        )
        result = classify_libvips_profiles(
            alpha_response([], alpha_bytes=512), [short_profile],
        )
        self.assertEqual(result["status"], "no_match")
        self.assertEqual(
            result["candidates"][0]["reason"], "response_too_short",
        )

    def test_malformed_image_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "not a decodable image"):
            classify_libvips_profiles(b"not an image", [self.current])

    def test_base_recovery_is_invariant_across_generated_layouts(self) -> None:
        generator = random.Random(2157)
        anchors = self.current.libvips.leak.anchors
        for _ in range(50):
            base = generator.randrange(
                0x0000500000000000,
                0x00007FFFFFF00000,
                0x1000,
            )
            positions = generator.sample(range(0, SYNTHETIC_ALPHA_BYTES, 8), 6)
            placements = [
                (positions[index], base + anchor.offset)
                for index, anchor in enumerate(anchors)
            ]
            placements.extend((position, generator.getrandbits(64)) for position in positions[3:])
            generator.shuffle(placements)
            result = classify_libvips_profiles(alpha_response(placements), [self.current])
            self.assertEqual(result["selected_base"], hex(base))

    def test_candidate_order_does_not_change_selection(self) -> None:
        other = replace(self.current, profile_id="other", libvips=self.immich.libvips)
        forward = classify_libvips_profiles(
            self.current_response(), [self.current, other],
        )
        reverse = classify_libvips_profiles(
            self.current_response(), [other, self.current],
        )
        self.assertEqual(forward["status"], reverse["status"])
        self.assertEqual(
            forward["selected_profile_id"], reverse["selected_profile_id"],
        )
        self.assertEqual(forward["selected_base"], reverse["selected_base"])


if __name__ == "__main__":
    unittest.main()
