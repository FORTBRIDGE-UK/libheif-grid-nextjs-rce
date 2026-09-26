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

    def test_unsupported_chunk_header_size_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "payload", "chunk_header_size"), 8,
        )
        with self.assertRaisesRegex(ProfileError, "must be 16"):
            load_manifest(path)

    def test_unsafe_library_component_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "application", "library_name"),
            "nested/x.jpg",
        )
        with self.assertRaisesRegex(ProfileError, "safe path component"):
            load_manifest(path)

    def test_header_injection_filename_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "application", "library_name"),
            'x.jpg"\r\nX-Evil: yes',
        )
        with self.assertRaisesRegex(ProfileError, "safe path component"):
            load_manifest(path)

    def test_network_path_endpoint_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "application", "upload_endpoint"),
            "//example.test/upload",
        )
        with self.assertRaisesRegex(ProfileError, "absolute URL path"):
            load_manifest(path)

    def test_pie_node_without_base_primitive_is_rejected(self) -> None:
        path = self.mutate(
            ("profiles", self.profile_id, "node", "elf_type"), "ET_DYN",
        )
        with self.assertRaisesRegex(ProfileError, "no Node PIE base-disclosure"):
            load_manifest(path)

    def test_unknown_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(ProfileError, "unknown native-stack profile"):
            load_profile("does-not-exist")


if __name__ == "__main__":
    unittest.main()
