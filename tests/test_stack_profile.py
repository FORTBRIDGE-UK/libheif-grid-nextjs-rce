from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from stack_profile import DEFAULT_MANIFEST, ProfileError, load_manifest, load_profile


class ProfileLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
        self.profile_id = self.document["default_profile"]

    def write_manifest(self, document: dict[str, object]) -> Path:
        temporary = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8",
        )
        with temporary:
            json.dump(document, temporary)
        self.addCleanup(Path(temporary.name).unlink)
        return Path(temporary.name)

    def mutate(self, path: tuple[str, ...], value: object) -> Path:
        document = copy.deepcopy(self.document)
        parent = document
        for component in path[:-1]:
            parent = parent[component]
        parent[path[-1]] = value
        return self.write_manifest(document)

    def test_default_and_explicit_selection(self) -> None:
        manifest = load_manifest()
        default = load_profile()
        explicit = load_profile(self.profile_id)
        self.assertEqual(manifest.default_profile, self.profile_id)
        self.assertEqual(default, explicit)

    def test_unknown_nested_key_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "payload", "surprise"), 1,
        )
        with self.assertRaisesRegex(ProfileError, "unknown keys: surprise"):
            load_manifest(path)

    def test_missing_required_field_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        del document["profiles"][self.profile_id]["node"]["build_id"]
        with self.assertRaisesRegex(ProfileError, "missing keys: build_id"):
            load_manifest(self.write_manifest(document))

    def test_malformed_integer_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "payload", "tile_width"),
            "not-an-integer",
        )
        with self.assertRaisesRegex(ProfileError, "invalid integer"):
            load_manifest(path)

    def test_malformed_digest_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "node", "sha256"), "xyz",
        )
        with self.assertRaisesRegex(ProfileError, "lowercase hexadecimal"):
            load_manifest(path)

    def test_inconsistent_geometry_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "payload", "canvas_stride"), 1,
        )
        with self.assertRaisesRegex(ProfileError, "shorter than a chroma row"):
            load_manifest(path)

    def test_legacy_static_heap_selector_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        document["profiles"][self.profile_id]["payload"][
            "fake_node_low16"
        ] = "0x5970"
        with self.assertRaisesRegex(ProfileError, "unknown keys: fake_node_low16"):
            load_manifest(self.write_manifest(document))

    def test_heap_calibration_requires_positive_observation_count(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "heap_calibration",
                "minimum_observations",
            ),
            0,
        )
        with self.assertRaisesRegex(ProfileError, "positive integer"):
            load_manifest(path)

    def test_heap_delta_must_be_signed_integer(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "heap_calibration",
                "fake_node_delta_from_anchor_page",
            ),
            "not-an-integer",
        )
        with self.assertRaisesRegex(ProfileError, "invalid integer"):
            load_manifest(path)

    def test_heap_anchor_rank_must_be_nonnegative(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "heap_calibration",
                "anchor_rank",
            ),
            -1,
        )
        with self.assertRaisesRegex(ProfileError, "non-negative integer"):
            load_manifest(path)

    def test_unsupported_chunk_header_size_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "payload", "chunk_header_size"), 8,
        )
        with self.assertRaisesRegex(ProfileError, "must be 16"):
            load_manifest(path)

    def test_unsafe_library_component_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "application", "library_name"),
            "nested/x",
        )
        with self.assertRaisesRegex(ProfileError, "safe path component"):
            load_manifest(path)

    def test_header_injection_filename_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "application", "library_name"),
            'x"\r\nX-Evil: yes',
        )
        with self.assertRaisesRegex(ProfileError, "safe path component"):
            load_manifest(path)

    def test_unsafe_upload_directory_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "application", "upload_directory"),
            "uploads/../tmp",
        )
        with self.assertRaisesRegex(ProfileError, "safe relative path"):
            load_manifest(path)

    def test_absolute_upload_directory_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "application", "upload_directory"),
            "/tmp",
        )
        with self.assertRaisesRegex(ProfileError, "safe relative path"):
            load_manifest(path)

    def test_network_path_endpoint_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "application", "upload_endpoint"),
            "//example.test/upload",
        )
        with self.assertRaisesRegex(ProfileError, "absolute URL path"):
            load_manifest(path)

    def test_pie_node_is_allowed_when_control_target_is_in_libvips(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "node", "elf_type"), "ET_DYN",
        )
        self.assertEqual(
            load_manifest(path).profiles[self.profile_id].node.elf_type,
            "ET_DYN",
        )

    def test_unsupported_node_elf_type_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "node", "elf_type"), "ET_CORE",
        )
        with self.assertRaisesRegex(ProfileError, "ET_EXEC or ET_DYN"):
            load_manifest(path)

    def test_legacy_absolute_node_loader_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        document["profiles"][self.profile_id]["node"]["unix_dl_open"] = {
            "symbol": "unixDlOpen",
            "address": "0x1fb95b0",
            "bytes": "554889e54889f7be020100005de98ee97bfe",
        }
        with self.assertRaisesRegex(ProfileError, "unknown keys: unix_dl_open"):
            load_manifest(self.write_manifest(document))

    def test_control_target_must_be_in_libvips(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "libvips", "control_target",
                "module",
            ),
            "node",
        )
        with self.assertRaisesRegex(ProfileError, "must be libvips"):
            load_manifest(path)

    def test_control_target_requires_declared_calling_convention(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "libvips", "control_target",
                "abi",
            ),
            "unknown",
        )
        with self.assertRaisesRegex(
            ProfileError, "path_rdi_flags_esi_error_rdx",
        ):
            load_manifest(path)

    def test_control_target_requires_validating_bytes(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "libvips", "control_target",
                "bytes",
            ),
            "0011",
        )
        with self.assertRaisesRegex(ProfileError, "at least eight bytes"):
            load_manifest(path)

    def test_unknown_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(ProfileError, "unknown native-stack profile"):
            load_profile("does-not-exist")

    def test_old_schema_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        document["schema"] = 1
        with self.assertRaisesRegex(ProfileError, "unsupported profile schema"):
            load_manifest(self.write_manifest(document))

    def test_leak_requires_two_distinct_anchors(self) -> None:
        anchors = [{"offset": "0x1000", "minimum_repetitions": 1}]
        path = self.mutate(
            ("profiles", self.profile_id, "libvips", "leak", "anchors"),
            anchors,
        )
        with self.assertRaisesRegex(ProfileError, "at least two entries"):
            load_manifest(path)

    def test_duplicate_anchor_offsets_are_rejected(self) -> None:
        anchors = [
            {"offset": "0x1000", "minimum_repetitions": 1},
            {"offset": "0x1000", "minimum_repetitions": 2},
        ]
        path = self.mutate(
            ("profiles", self.profile_id, "libvips", "leak", "anchors"),
            anchors,
        )
        with self.assertRaisesRegex(ProfileError, "offsets must be distinct"):
            load_manifest(path)

    def test_required_anchor_count_must_fit_declared_anchors(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "libvips", "leak",
                "required_anchors",
            ),
            4,
        )
        with self.assertRaisesRegex(ProfileError, "between two and the anchor count"):
            load_manifest(path)

    def test_anchor_repetition_must_be_positive(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "libvips", "leak", "anchors",
                0, "minimum_repetitions",
            ),
            0,
        )
        with self.assertRaisesRegex(ProfileError, "positive integer"):
            load_manifest(path)

    def test_scan_values_must_be_qword_aligned(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "libvips", "leak", "scan_end"),
            1025,
        )
        with self.assertRaisesRegex(ProfileError, "eight-byte aligned"):
            load_manifest(path)

    def test_scan_range_must_be_nonempty(self) -> None:
        document = copy.deepcopy(self.document)
        leak = document["profiles"][self.profile_id]["libvips"]["leak"]
        leak["scan_start"] = 1024
        leak["scan_end"] = 1024
        with self.assertRaisesRegex(ProfileError, "scan range is empty"):
            load_manifest(self.write_manifest(document))

    def test_supporting_hints_must_contain_strings(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "libvips", "leak",
                "supporting_hints",
            ),
            {"os": 13},
        )
        with self.assertRaisesRegex(ProfileError, "non-empty string"):
            load_manifest(path)

    def test_pie_manifest_is_strict_and_exact(self) -> None:
        path = DEFAULT_MANIFEST.with_name("native_stack_profiles_pie.json")
        profile = load_profile(manifest_path=path)
        self.assertEqual(profile.node.elf_type, "ET_DYN")
        self.assertEqual(profile.heap_calibration.record_variant, "pie_tail")
        self.assertEqual(
            profile.heap_calibration.selector_strategy,
            "profile_page_lane",
        )
        self.assertEqual(profile.heap_calibration.anchor_page_low16, 0x6000)
        self.assertEqual(profile.heap_calibration.scan_start, 0xE0000)

    def test_unknown_heap_record_variant_is_rejected(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "heap_calibration",
                "record_variant",
            ),
            "guess",
        )
        with self.assertRaisesRegex(ProfileError, "marked_arena or pie_tail"):
            load_manifest(path)

    def test_unknown_heap_selector_strategy_is_rejected(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "heap_calibration",
                "selector_strategy",
            ),
            "forced",
        )
        with self.assertRaisesRegex(
            ProfileError, "response_record or profile_page_lane",
        ):
            load_manifest(path)

    def test_invalid_heap_scan_range_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        calibration = document["profiles"][self.profile_id]["heap_calibration"]
        calibration["scan_start"] = calibration["scan_end"]
        with self.assertRaisesRegex(ProfileError, "scan range is empty"):
            load_manifest(self.write_manifest(document))

    def test_marked_record_rejects_pie_page_lane(self) -> None:
        path = self.mutate(
            (
                "profiles", self.profile_id, "heap_calibration",
                "anchor_page_low16",
            ),
            "0x6000",
        )
        with self.assertRaisesRegex(ProfileError, "must be zero"):
            load_manifest(path)


if __name__ == "__main__":
    unittest.main()
