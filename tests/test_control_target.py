from __future__ import annotations

import unittest

from control_target import derive_control_target
from stack_profile import load_profile


class ControlTargetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_profile()
        self.base = 0x0000700000000000

    def test_libvips_target_is_base_plus_profile_offset(self) -> None:
        target = derive_control_target(self.base, self.profile)
        self.assertEqual(target.module, "libvips")
        self.assertEqual(target.symbol, "g_spawn_command_line_async")
        self.assertEqual(target.offset, 0x349A13)
        self.assertEqual(target.address, self.base + 0x349A13)
        self.assertEqual(
            target.evidence()["derivation"],
            "0x700000000000 + 0x349a13 = 0x700000349a13",
        )

    def test_unaligned_module_base_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "not page-aligned"):
            derive_control_target(self.base + 1, self.profile)

    def test_noncanonical_module_base_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "canonical profile range"):
            derive_control_target(0x1000, self.profile)

    def test_boolean_module_base_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be an integer"):
            derive_control_target(True, self.profile)


if __name__ == "__main__":
    unittest.main()
