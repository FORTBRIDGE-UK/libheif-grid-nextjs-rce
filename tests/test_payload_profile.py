from __future__ import annotations

import hashlib
import unittest

from rce_payload import build_rce_payload
from stack_profile import load_profile


class PayloadProfileTests(unittest.TestCase):
    def test_profile_payload_matches_pre_refactor_bytes(self) -> None:
        payload = build_rce_payload(
            0x0000700000000000,
            0x5970,
            "uploads/x.jpg",
            load_profile(),
        )
        self.assertEqual(len(payload), 4096)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "605d9c5667c70a2901852676421716b91e94f3751eb6a0955921f2a6b772335c",
        )

    def test_unaligned_libvips_base_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "not page-aligned"):
            build_rce_payload(
                0x0000700000000001, 0x5970, profile=load_profile(),
            )

    def test_selector_above_two_bytes_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsigned two-byte"):
            build_rce_payload(
                0x0000700000000000, 0x10000, profile=load_profile(),
            )

    def test_negative_selector_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsigned two-byte"):
            build_rce_payload(
                0x0000700000000000, -1, profile=load_profile(),
            )


if __name__ == "__main__":
    unittest.main()
