#!/usr/bin/env python3
"""Strict loader for versioned native-stack exploit profiles."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE / "profiles" / "native_stack_profiles.json"
SUPPORTED_SCHEMA = 6
MAX_LEAK_SCAN_BYTES = 16 * 1024 * 1024
_HEX_RE = re.compile(r"^[0-9a-f]+$")
_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class ProfileError(ValueError):
    """Raised when a manifest cannot safely describe a target stack."""


@dataclass(frozen=True)
class PackageProfile:
    version: str
    package_manifest_sha256: str


@dataclass(frozen=True)
class ApplicationProfile:
    upload_endpoint: str
    optimize_endpoint: str
    upload_directory: str
    library_name: str
    library_content_type: str
    max_library_path_bytes: int

    @property
    def library_path(self) -> str:
        return f"{self.upload_directory}/{self.library_name}"


@dataclass(frozen=True)
class NodeProfile:
    version: str
    elf_type: str
    filename: str
    build_id: str
    sha256: str


@dataclass(frozen=True)
class ControlTargetProfile:
    module: str
    symbol: str
    exported: bool
    offset: int
    abi: str
    bytes: bytes


@dataclass(frozen=True)
class LeakAnchorProfile:
    offset: int
    minimum_repetitions: int


@dataclass(frozen=True)
class LeakProfile:
    anchors: tuple[LeakAnchorProfile, ...]
    required_anchors: int
    scan_start: int
    scan_end: int
    scan_step: int
    pointer_min: int
    pointer_max: int
    base_alignment: int
    supporting_hints: dict[str, str]

    @property
    def signature_offsets(self) -> tuple[int, ...]:
        """Compatibility view used by the payload regression tests."""
        return tuple(anchor.offset for anchor in self.anchors)


@dataclass(frozen=True)
class LibvipsProfile:
    version: str
    package: str
    package_version: str
    filename: str
    build_id: str
    sha256: str
    package_manifest_sha256: str
    versions_manifest_sha256: str
    memcpy_symbol: str
    memcpy_got_offset: int
    memcpy_relocation: str
    control_target: ControlTargetProfile
    leak: LeakProfile


@dataclass(frozen=True)
class LibheifProfile:
    version: str
    versions_manifest_key: str


@dataclass(frozen=True)
class GlibcProfile:
    version: str
    filename: str
    build_id: str
    sha256: str
    root_chunk_size_and_flags: int


@dataclass(frozen=True)
class LibstdcxxProfile:
    version: str
    filename: str
    build_id: str
    sha256: str


@dataclass(frozen=True)
class RbTreeNodeLayout:
    size: int
    left_offset: int
    right_offset: int
    key_offset: int


@dataclass(frozen=True)
class ImagePlaneLayout:
    datatype_offset: int
    bits_per_pixel_offset: int
    components_offset: int
    width_offset: int
    height_offset: int
    mem_offset: int
    stride_offset: int
    unsigned_datatype: int
    cr_channel: int


@dataclass(frozen=True)
class AbiProfile:
    rb_tree_node: RbTreeNodeLayout
    image_plane: ImagePlaneLayout


@dataclass(frozen=True)
class HeapCalibrationProfile:
    record_variant: str
    selector_strategy: str
    minimum_observations: int
    anchor_rank: int
    scan_start: int
    scan_end: int
    anchor_alignment: int
    anchor_page_offset_min: int
    anchor_page_offset_max: int
    anchor_page_low16: int
    arena_alignment: int
    arena_sentinel_offset: int
    record_chunk_size_and_flags: int
    anchor_peer_delta: int
    related_pointer_delta_min: int
    related_pointer_delta_max: int
    libvips_record_offsets: tuple[int, int, int]
    record_marker: int
    record_prefix_qwords: tuple[int, ...]
    fake_node_delta_from_anchor_page: int


@dataclass(frozen=True)
class PayloadProfile:
    tile_width: int
    tile_height: int
    grid_rows: int
    grid_columns: int
    canvas_stride: int
    fake_node_local_row: int
    path_field_bytes: int
    write_target_backoff: int
    preserved_prefix_bytes: int
    chunk_header_offset: int
    chunk_header_size: int
    redirect_pointer_offset: int
    redirect_pointer_size: int

    @property
    def chroma_width(self) -> int:
        return (self.tile_width + 1) // 2

    @property
    def chroma_height(self) -> int:
        return (self.tile_height + 1) // 2

    @property
    def canvas_chroma_height(self) -> int:
        return (self.tile_height * self.grid_rows + 1) // 2


@dataclass(frozen=True)
class NativeStackProfile:
    profile_id: str
    description: str
    architecture: str
    next_package: PackageProfile
    sharp_package: PackageProfile
    application: ApplicationProfile
    node: NodeProfile
    libvips: LibvipsProfile
    libheif: LibheifProfile
    glibc: GlibcProfile
    libstdcxx: LibstdcxxProfile
    abi: AbiProfile
    heap_calibration: HeapCalibrationProfile
    payload: PayloadProfile


@dataclass(frozen=True)
class ProfileManifest:
    default_profile: str
    profiles: dict[str, NativeStackProfile]


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfileError(f"{path} must be an object")
    return value


def _exact_keys(value: dict[str, Any], path: str,
                required: set[str]) -> None:
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required)
    if missing:
        raise ProfileError(f"{path} missing keys: {', '.join(missing)}")
    if unknown:
        raise ProfileError(f"{path} unknown keys: {', '.join(unknown)}")


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProfileError(f"{path} must be a non-empty string")
    return value


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise ProfileError(f"{path} must be a boolean")
    return value


def _integer(value: Any, path: str, *, positive: bool = False) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"{path} must be an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 0)
        except ValueError as error:
            raise ProfileError(f"{path} contains an invalid integer") from error
    else:
        raise ProfileError(f"{path} must be an integer or integer string")
    if result < 0 or (positive and result == 0):
        qualifier = "positive " if positive else "non-negative "
        raise ProfileError(f"{path} must be a {qualifier}integer")
    return result


def _signed_integer(value: Any, path: str) -> int:
    if isinstance(value, bool):
        raise ProfileError(f"{path} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise ProfileError(f"{path} contains an invalid integer") from error
    raise ProfileError(f"{path} must be an integer or integer string")


def _hex_digest(value: Any, path: str, length: int | None = None) -> str:
    digest = _string(value, path).lower()
    if not _HEX_RE.fullmatch(digest):
        raise ProfileError(f"{path} must contain lowercase hexadecimal")
    if length is not None and len(digest) != length:
        raise ProfileError(f"{path} must contain exactly {length} hex characters")
    return digest


def _signature(value: Any, path: str) -> bytes:
    encoded = _hex_digest(value, path)
    if len(encoded) % 2:
        raise ProfileError(f"{path} must contain whole bytes")
    result = bytes.fromhex(encoded)
    if len(result) < 8:
        raise ProfileError(f"{path} must contain at least eight bytes")
    return result


def _package(value: Any, path: str) -> PackageProfile:
    data = _mapping(value, path)
    _exact_keys(data, path, {"version", "package_manifest_sha256"})
    return PackageProfile(
        version=_string(data["version"], f"{path}.version"),
        package_manifest_sha256=_hex_digest(
            data["package_manifest_sha256"],
            f"{path}.package_manifest_sha256",
            64,
        ),
    )


def _application(value: Any, path: str) -> ApplicationProfile:
    data = _mapping(value, path)
    _exact_keys(data, path, {
        "upload_endpoint", "optimize_endpoint", "upload_directory",
        "library_name", "library_content_type", "max_library_path_bytes",
    })
    result = ApplicationProfile(
        upload_endpoint=_string(data["upload_endpoint"], f"{path}.upload_endpoint"),
        optimize_endpoint=_string(
            data["optimize_endpoint"], f"{path}.optimize_endpoint",
        ),
        upload_directory=_string(
            data["upload_directory"], f"{path}.upload_directory",
        ),
        library_name=_string(data["library_name"], f"{path}.library_name"),
        library_content_type=_string(
            data["library_content_type"], f"{path}.library_content_type",
        ),
        max_library_path_bytes=_integer(
            data["max_library_path_bytes"],
            f"{path}.max_library_path_bytes",
            positive=True,
        ),
    )
    for field_name, endpoint in (
        ("upload_endpoint", result.upload_endpoint),
        ("optimize_endpoint", result.optimize_endpoint),
    ):
        parsed = urlsplit(endpoint)
        if (
            not endpoint.startswith("/")
            or endpoint.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.query
            or parsed.fragment
        ):
            raise ProfileError(f"{path}.{field_name} must be one absolute URL path")
    if not result.upload_directory:
        raise ProfileError(f"{path}.upload_directory must not be empty")
    directory = PurePosixPath(result.upload_directory)
    if (
        directory.is_absolute()
        or ".." in directory.parts
        or any(
            not _FILENAME_RE.fullmatch(component)
            or component in {".", ".."}
            for component in directory.parts
        )
    ):
        raise ProfileError(f"{path}.upload_directory must be a safe relative path")
    if (
        not _FILENAME_RE.fullmatch(result.library_name)
        or result.library_name in {".", ".."}
    ):
        raise ProfileError(f"{path}.library_name must be one safe path component")
    if PurePosixPath(result.library_name).suffix.lower() not in {
        ".avif", ".heic", ".heif", ".jpeg", ".jpg", ".png",
    }:
        raise ProfileError(f"{path}.library_name must use an image suffix")
    if result.library_content_type not in {
        "image/avif", "image/heic", "image/heif", "image/jpeg", "image/png",
    }:
        raise ProfileError(f"{path}.library_content_type must be an image type")
    remote_path = PurePosixPath(result.library_path)
    if remote_path.is_absolute() or ".." in remote_path.parts:
        raise ProfileError(f"{path} contains an unsafe library path")
    try:
        encoded_length = len(result.library_path.encode("ascii")) + 1
    except UnicodeEncodeError as error:
        raise ProfileError(f"{path} library path must be ASCII") from error
    if encoded_length > result.max_library_path_bytes:
        raise ProfileError(f"{path} default library path exceeds its maximum")
    return result


def _node(value: Any, path: str) -> NodeProfile:
    data = _mapping(value, path)
    _exact_keys(data, path, {
        "version", "elf_type", "filename", "build_id", "sha256",
    })
    elf_type = _string(data["elf_type"], f"{path}.elf_type")
    if elf_type not in {"ET_EXEC", "ET_DYN"}:
        raise ProfileError(f"{path}.elf_type must be ET_EXEC or ET_DYN")
    return NodeProfile(
        version=_string(data["version"], f"{path}.version"),
        elf_type=elf_type,
        filename=_string(data["filename"], f"{path}.filename"),
        build_id=_hex_digest(data["build_id"], f"{path}.build_id"),
        sha256=_hex_digest(data["sha256"], f"{path}.sha256", 64),
    )


def _libvips(value: Any, path: str) -> LibvipsProfile:
    data = _mapping(value, path)
    _exact_keys(data, path, {
        "version", "package", "package_version", "filename", "build_id",
        "sha256", "package_manifest_sha256", "versions_manifest_sha256",
        "memcpy_got", "control_target", "leak",
    })
    got = _mapping(data["memcpy_got"], f"{path}.memcpy_got")
    _exact_keys(got, f"{path}.memcpy_got", {
        "symbol", "offset", "relocation",
    })
    control = _mapping(data["control_target"], f"{path}.control_target")
    _exact_keys(control, f"{path}.control_target", {
        "module", "symbol", "exported", "offset", "abi", "bytes",
    })
    module = _string(control["module"], f"{path}.control_target.module")
    if module != "libvips":
        raise ProfileError(f"{path}.control_target.module must be libvips")
    abi = _string(control["abi"], f"{path}.control_target.abi")
    if abi != "path_rdi_flags_esi_error_rdx":
        raise ProfileError(
            f"{path}.control_target.abi must be path_rdi_flags_esi_error_rdx",
        )
    leak = _mapping(data["leak"], f"{path}.leak")
    _exact_keys(leak, f"{path}.leak", {
        "anchors", "required_anchors", "scan_start", "scan_end",
        "scan_step", "pointer_min", "pointer_max", "base_alignment",
        "supporting_hints",
    })
    raw_anchors = leak["anchors"]
    if not isinstance(raw_anchors, list) or len(raw_anchors) < 2:
        raise ProfileError(f"{path}.leak.anchors must have at least two entries")
    anchors = []
    for index, value in enumerate(raw_anchors):
        anchor_path = f"{path}.leak.anchors[{index}]"
        anchor = _mapping(value, anchor_path)
        _exact_keys(anchor, anchor_path, {"offset", "minimum_repetitions"})
        anchors.append(LeakAnchorProfile(
            offset=_integer(
                anchor["offset"], f"{anchor_path}.offset", positive=True,
            ),
            minimum_repetitions=_integer(
                anchor["minimum_repetitions"],
                f"{anchor_path}.minimum_repetitions",
                positive=True,
            ),
        ))
    if len({anchor.offset for anchor in anchors}) != len(anchors):
        raise ProfileError(f"{path}.leak anchor offsets must be distinct")
    required_anchors = _integer(
        leak["required_anchors"],
        f"{path}.leak.required_anchors",
        positive=True,
    )
    if required_anchors < 2 or required_anchors > len(anchors):
        raise ProfileError(
            f"{path}.leak.required_anchors must be between two and the "
            "anchor count",
        )
    scan_start = _integer(leak["scan_start"], f"{path}.leak.scan_start")
    scan_end = _integer(
        leak["scan_end"], f"{path}.leak.scan_end", positive=True,
    )
    scan_step = _integer(
        leak["scan_step"], f"{path}.leak.scan_step", positive=True,
    )
    if any(value % 8 for value in (scan_start, scan_end, scan_step)):
        raise ProfileError(f"{path}.leak scan values must be eight-byte aligned")
    if scan_start >= scan_end:
        raise ProfileError(f"{path}.leak scan range is empty")
    if scan_end - scan_start > MAX_LEAK_SCAN_BYTES:
        raise ProfileError(
            f"{path}.leak scan range exceeds {MAX_LEAK_SCAN_BYTES} bytes",
        )
    pointer_min = _integer(leak["pointer_min"], f"{path}.leak.pointer_min")
    pointer_max = _integer(leak["pointer_max"], f"{path}.leak.pointer_max")
    if pointer_min >= pointer_max:
        raise ProfileError(f"{path}.leak pointer range is empty")
    alignment = _integer(
        leak["base_alignment"], f"{path}.leak.base_alignment", positive=True,
    )
    if alignment & (alignment - 1):
        raise ProfileError(f"{path}.leak.base_alignment must be a power of two")
    raw_hints = _mapping(
        leak["supporting_hints"], f"{path}.leak.supporting_hints",
    )
    supporting_hints = {}
    for key, value in raw_hints.items():
        hint_path = f"{path}.leak.supporting_hints.{key}"
        if not isinstance(key, str) or not key:
            raise ProfileError(
                f"{path}.leak.supporting_hints keys must be non-empty strings",
            )
        supporting_hints[key] = _string(value, hint_path)
    return LibvipsProfile(
        version=_string(data["version"], f"{path}.version"),
        package=_string(data["package"], f"{path}.package"),
        package_version=_string(data["package_version"], f"{path}.package_version"),
        filename=_string(data["filename"], f"{path}.filename"),
        build_id=_hex_digest(data["build_id"], f"{path}.build_id"),
        sha256=_hex_digest(data["sha256"], f"{path}.sha256", 64),
        package_manifest_sha256=_hex_digest(
            data["package_manifest_sha256"],
            f"{path}.package_manifest_sha256",
            64,
        ),
        versions_manifest_sha256=_hex_digest(
            data["versions_manifest_sha256"],
            f"{path}.versions_manifest_sha256",
            64,
        ),
        memcpy_symbol=_string(got["symbol"], f"{path}.memcpy_got.symbol"),
        memcpy_got_offset=_integer(
            got["offset"], f"{path}.memcpy_got.offset", positive=True,
        ),
        memcpy_relocation=_string(
            got["relocation"], f"{path}.memcpy_got.relocation",
        ),
        control_target=ControlTargetProfile(
            module=module,
            symbol=_string(
                control["symbol"], f"{path}.control_target.symbol",
            ),
            exported=_boolean(
                control["exported"], f"{path}.control_target.exported",
            ),
            offset=_integer(
                control["offset"],
                f"{path}.control_target.offset",
                positive=True,
            ),
            abi=abi,
            bytes=_signature(
                control["bytes"], f"{path}.control_target.bytes",
            ),
        ),
        leak=LeakProfile(
            anchors=tuple(anchors),
            required_anchors=required_anchors,
            scan_start=scan_start,
            scan_end=scan_end,
            scan_step=scan_step,
            pointer_min=pointer_min,
            pointer_max=pointer_max,
            base_alignment=alignment,
            supporting_hints=supporting_hints,
        ),
    )


def _libheif(value: Any, path: str) -> LibheifProfile:
    data = _mapping(value, path)
    _exact_keys(data, path, {"version", "versions_manifest_key"})
    return LibheifProfile(
        version=_string(data["version"], f"{path}.version"),
        versions_manifest_key=_string(
            data["versions_manifest_key"], f"{path}.versions_manifest_key",
        ),
    )


def _glibc(value: Any, path: str) -> GlibcProfile:
    data = _mapping(value, path)
    _exact_keys(data, path, {
        "version", "filename", "build_id", "sha256",
        "root_chunk_size_and_flags",
    })
    return GlibcProfile(
        version=_string(data["version"], f"{path}.version"),
        filename=_string(data["filename"], f"{path}.filename"),
        build_id=_hex_digest(data["build_id"], f"{path}.build_id"),
        sha256=_hex_digest(data["sha256"], f"{path}.sha256", 64),
        root_chunk_size_and_flags=_integer(
            data["root_chunk_size_and_flags"],
            f"{path}.root_chunk_size_and_flags",
            positive=True,
        ),
    )


def _libstdcxx(value: Any, path: str) -> LibstdcxxProfile:
    data = _mapping(value, path)
    _exact_keys(data, path, {"version", "filename", "build_id", "sha256"})
    return LibstdcxxProfile(
        version=_string(data["version"], f"{path}.version"),
        filename=_string(data["filename"], f"{path}.filename"),
        build_id=_hex_digest(data["build_id"], f"{path}.build_id"),
        sha256=_hex_digest(data["sha256"], f"{path}.sha256", 64),
    )


def _abi(value: Any, path: str) -> AbiProfile:
    data = _mapping(value, path)
    _exact_keys(data, path, {"rb_tree_node", "image_plane"})
    tree = _mapping(data["rb_tree_node"], f"{path}.rb_tree_node")
    _exact_keys(tree, f"{path}.rb_tree_node", {
        "size", "left_offset", "right_offset", "key_offset",
    })
    plane = _mapping(data["image_plane"], f"{path}.image_plane")
    plane_fields = {
        "datatype_offset", "bits_per_pixel_offset", "components_offset",
        "width_offset", "height_offset", "mem_offset", "stride_offset",
        "unsigned_datatype", "cr_channel",
    }
    _exact_keys(plane, f"{path}.image_plane", plane_fields)
    tree_layout = RbTreeNodeLayout(**{
        key: _integer(tree[key], f"{path}.rb_tree_node.{key}", positive=True)
        for key in tree
    })
    plane_layout = ImagePlaneLayout(**{
        key: _integer(plane[key], f"{path}.image_plane.{key}")
        for key in plane
    })
    occupied = [
        tree_layout.left_offset + 8,
        tree_layout.right_offset + 8,
        tree_layout.key_offset + 4,
        plane_layout.datatype_offset + 4,
        plane_layout.bits_per_pixel_offset + 1,
        plane_layout.components_offset + 1,
        plane_layout.width_offset + 4,
        plane_layout.height_offset + 4,
        plane_layout.mem_offset + 8,
        plane_layout.stride_offset + 4,
    ]
    if max(occupied) > tree_layout.size:
        raise ProfileError(f"{path} field lies beyond rb_tree_node.size")
    return AbiProfile(tree_layout, plane_layout)


def _heap_calibration(value: Any, path: str) -> HeapCalibrationProfile:
    data = _mapping(value, path)
    keys = {
        "record_variant", "selector_strategy", "minimum_observations",
        "anchor_rank",
        "scan_start", "scan_end", "anchor_alignment",
        "anchor_page_offset_min", "anchor_page_offset_max",
        "anchor_page_low16",
        "arena_alignment",
        "arena_sentinel_offset",
        "record_chunk_size_and_flags", "anchor_peer_delta",
        "related_pointer_delta_min", "related_pointer_delta_max",
        "libvips_record_offsets", "record_marker", "record_prefix_qwords",
        "fake_node_delta_from_anchor_page",
    }
    _exact_keys(data, path, keys)
    record_variant = _string(data["record_variant"], f"{path}.record_variant")
    if record_variant not in {"marked_arena", "pie_tail"}:
        raise ProfileError(
            f"{path}.record_variant must be marked_arena or pie_tail",
        )
    selector_strategy = _string(
        data["selector_strategy"], f"{path}.selector_strategy",
    )
    if selector_strategy not in {"response_record", "profile_page_lane"}:
        raise ProfileError(
            f"{path}.selector_strategy must be response_record or "
            "profile_page_lane",
        )
    scan_start = _integer(data["scan_start"], f"{path}.scan_start")
    scan_end = _integer(
        data["scan_end"], f"{path}.scan_end", positive=True,
    )
    if scan_start % 8 or scan_end % 8:
        raise ProfileError(f"{path} scan values must be eight-byte aligned")
    if scan_start >= scan_end:
        raise ProfileError(f"{path} scan range is empty")
    if scan_end - scan_start > MAX_LEAK_SCAN_BYTES:
        raise ProfileError(
            f"{path} scan range exceeds {MAX_LEAK_SCAN_BYTES} bytes",
        )
    raw_offsets = data["libvips_record_offsets"]
    if not isinstance(raw_offsets, list) or len(raw_offsets) != 3:
        raise ProfileError(
            f"{path}.libvips_record_offsets must contain exactly three entries",
        )
    offsets = tuple(
        _integer(item, f"{path}.libvips_record_offsets[{index}]", positive=True)
        for index, item in enumerate(raw_offsets)
    )
    if len(set(offsets)) != len(offsets):
        raise ProfileError(f"{path}.libvips_record_offsets must be distinct")
    alignment = _integer(
        data["arena_alignment"], f"{path}.arena_alignment", positive=True,
    )
    if alignment & (alignment - 1):
        raise ProfileError(f"{path}.arena_alignment must be a power of two")
    sentinel_offset = _integer(
        data["arena_sentinel_offset"],
        f"{path}.arena_sentinel_offset",
        positive=True,
    )
    if sentinel_offset >= alignment:
        raise ProfileError(f"{path}.arena_sentinel_offset exceeds the arena")
    peer_delta = _integer(
        data["anchor_peer_delta"], f"{path}.anchor_peer_delta", positive=True,
    )
    related_delta_min = _integer(
        data["related_pointer_delta_min"],
        f"{path}.related_pointer_delta_min",
        positive=True,
    )
    related_delta_max = _integer(
        data["related_pointer_delta_max"],
        f"{path}.related_pointer_delta_max",
        positive=True,
    )
    if related_delta_min >= related_delta_max:
        raise ProfileError(f"{path} related-pointer delta range is empty")
    anchor_alignment = _integer(
        data["anchor_alignment"], f"{path}.anchor_alignment", positive=True,
    )
    if anchor_alignment & (anchor_alignment - 1):
        raise ProfileError(f"{path}.anchor_alignment must be a power of two")
    if anchor_alignment >= alignment:
        raise ProfileError(f"{path}.anchor_alignment must be smaller than arena")
    page_offset_min = _integer(
        data["anchor_page_offset_min"],
        f"{path}.anchor_page_offset_min",
    )
    page_offset_max = _integer(
        data["anchor_page_offset_max"],
        f"{path}.anchor_page_offset_max",
        positive=True,
    )
    if not 0 <= page_offset_min < page_offset_max <= anchor_alignment:
        raise ProfileError(f"{path} anchor-page offset range is invalid")
    page_low16 = _integer(
        data["anchor_page_low16"], f"{path}.anchor_page_low16",
    )
    if page_low16 > 0xFFFF or page_low16 % anchor_alignment:
        raise ProfileError(
            f"{path}.anchor_page_low16 must be a page-aligned two-byte value",
        )
    raw_prefix = data["record_prefix_qwords"]
    if not isinstance(raw_prefix, list):
        raise ProfileError(f"{path}.record_prefix_qwords must be an array")
    prefix = tuple(
        _integer(item, f"{path}.record_prefix_qwords[{index}]")
        for index, item in enumerate(raw_prefix)
    )
    if any(item > 0xFFFFFFFFFFFFFFFF for item in prefix):
        raise ProfileError(f"{path}.record_prefix_qwords entries exceed eight bytes")
    if record_variant == "marked_arena":
        if prefix:
            raise ProfileError(
                f"{path}.record_prefix_qwords must be empty for marked_arena",
            )
        if page_low16 != 0:
            raise ProfileError(
                f"{path}.anchor_page_low16 must be zero for marked_arena",
            )
        if selector_strategy != "response_record":
            raise ProfileError(
                f"{path}.marked_arena requires response_record selection",
            )
    elif len(prefix) != 6:
        raise ProfileError(
            f"{path}.record_prefix_qwords must contain six entries for pie_tail",
        )
    if selector_strategy == "profile_page_lane" and page_low16 == 0:
        raise ProfileError(
            f"{path}.profile_page_lane requires a non-zero page lane",
        )
    fake_node_delta = _signed_integer(
        data["fake_node_delta_from_anchor_page"],
        f"{path}.fake_node_delta_from_anchor_page",
    )
    if fake_node_delta == 0 or abs(fake_node_delta) >= alignment:
        raise ProfileError(
            f"{path}.fake_node_delta_from_anchor_page must be a non-zero "
            "in-arena relation",
        )
    return HeapCalibrationProfile(
        record_variant=record_variant,
        selector_strategy=selector_strategy,
        minimum_observations=_integer(
            data["minimum_observations"],
            f"{path}.minimum_observations",
            positive=True,
        ),
        anchor_rank=_integer(data["anchor_rank"], f"{path}.anchor_rank"),
        scan_start=scan_start,
        scan_end=scan_end,
        anchor_alignment=anchor_alignment,
        anchor_page_offset_min=page_offset_min,
        anchor_page_offset_max=page_offset_max,
        anchor_page_low16=page_low16,
        arena_alignment=alignment,
        arena_sentinel_offset=sentinel_offset,
        record_chunk_size_and_flags=_integer(
            data["record_chunk_size_and_flags"],
            f"{path}.record_chunk_size_and_flags",
            positive=True,
        ),
        anchor_peer_delta=peer_delta,
        related_pointer_delta_min=related_delta_min,
        related_pointer_delta_max=related_delta_max,
        libvips_record_offsets=offsets,
        record_marker=_integer(
            data["record_marker"], f"{path}.record_marker", positive=True,
        ),
        record_prefix_qwords=prefix,
        fake_node_delta_from_anchor_page=fake_node_delta,
    )


def _payload(value: Any, path: str) -> PayloadProfile:
    data = _mapping(value, path)
    keys = {
        "tile_width", "tile_height", "grid_rows", "grid_columns",
        "canvas_stride", "fake_node_local_row",
        "path_field_bytes", "write_target_backoff", "preserved_prefix_bytes",
        "chunk_header_offset", "chunk_header_size", "redirect_pointer_offset",
        "redirect_pointer_size",
    }
    _exact_keys(data, path, keys)
    positive = keys - {"fake_node_local_row"}
    values = {
        key: _integer(data[key], f"{path}.{key}", positive=key in positive)
        for key in keys
    }
    result = PayloadProfile(**values)
    if result.chunk_header_size != 16:
        raise ProfileError(f"{path}.chunk_header_size must be 16")
    if result.redirect_pointer_size != 2:
        raise ProfileError(f"{path}.redirect_pointer_size must be two")
    if result.path_field_bytes + 8 > result.chroma_width:
        raise ProfileError(f"{path} control-target row exceeds the chroma width")
    if result.canvas_stride < result.chroma_width:
        raise ProfileError(f"{path}.canvas_stride is shorter than a chroma row")
    if result.write_target_backoff != result.path_field_bytes:
        raise ProfileError(f"{path} GOT backoff must equal the path field")
    if result.chunk_header_offset != result.preserved_prefix_bytes:
        raise ProfileError(f"{path} chunk header must follow the preserved prefix")
    if result.chunk_header_offset + result.chunk_header_size > result.chroma_width:
        raise ProfileError(f"{path} chunk header exceeds the overflow row")
    if result.redirect_pointer_offset + result.redirect_pointer_size > result.chroma_width:
        raise ProfileError(f"{path} redirect pointer exceeds the overflow row")
    if result.fake_node_local_row >= result.chroma_height:
        raise ProfileError(f"{path}.fake_node_local_row exceeds the tile")
    return result


def _profile(profile_id: str, value: Any) -> NativeStackProfile:
    path = f"profiles.{profile_id}"
    data = _mapping(value, path)
    _exact_keys(data, path, {
        "description", "architecture", "packages", "application", "node",
        "libvips", "libheif", "glibc", "libstdcxx", "abi",
        "heap_calibration", "payload",
    })
    architecture = _string(data["architecture"], f"{path}.architecture")
    if architecture != "x86_64":
        raise ProfileError(f"{path}.architecture is unsupported: {architecture}")
    packages = _mapping(data["packages"], f"{path}.packages")
    _exact_keys(packages, f"{path}.packages", {"next", "sharp"})
    result = NativeStackProfile(
        profile_id=profile_id,
        description=_string(data["description"], f"{path}.description"),
        architecture=architecture,
        next_package=_package(packages["next"], f"{path}.packages.next"),
        sharp_package=_package(packages["sharp"], f"{path}.packages.sharp"),
        application=_application(data["application"], f"{path}.application"),
        node=_node(data["node"], f"{path}.node"),
        libvips=_libvips(data["libvips"], f"{path}.libvips"),
        libheif=_libheif(data["libheif"], f"{path}.libheif"),
        glibc=_glibc(data["glibc"], f"{path}.glibc"),
        libstdcxx=_libstdcxx(data["libstdcxx"], f"{path}.libstdcxx"),
        abi=_abi(data["abi"], f"{path}.abi"),
        heap_calibration=_heap_calibration(
            data["heap_calibration"], f"{path}.heap_calibration",
        ),
        payload=_payload(data["payload"], f"{path}.payload"),
    )
    if (
        result.application.max_library_path_bytes
        > result.payload.path_field_bytes
    ):
        raise ProfileError(f"{path} application path exceeds payload capacity")
    if result.glibc.root_chunk_size_and_flags > 0xFFFFFFFFFFFFFFFF:
        raise ProfileError(f"{path}.glibc root chunk field exceeds eight bytes")
    if (
        result.heap_calibration.record_variant == "pie_tail"
        and result.heap_calibration.record_prefix_qwords[1]
        != result.glibc.root_chunk_size_and_flags
    ):
        raise ProfileError(
            f"{path} PIE record prefix disagrees with glibc root chunk field",
        )
    return result


def load_manifest(path: Path | None = None) -> ProfileManifest:
    manifest_path = path or DEFAULT_MANIFEST
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProfileError(f"cannot load profile manifest {manifest_path}: {error}") from error
    root = _mapping(data, "manifest")
    _exact_keys(root, "manifest", {"schema", "default_profile", "profiles"})
    schema = _integer(root["schema"], "manifest.schema")
    if schema != SUPPORTED_SCHEMA:
        raise ProfileError(f"unsupported profile schema: {schema}")
    default_profile = _string(root["default_profile"], "manifest.default_profile")
    raw_profiles = _mapping(root["profiles"], "manifest.profiles")
    if not raw_profiles:
        raise ProfileError("manifest.profiles must not be empty")
    profiles = {
        profile_id: _profile(profile_id, value)
        for profile_id, value in raw_profiles.items()
    }
    if default_profile not in profiles:
        raise ProfileError("manifest.default_profile does not exist")
    return ProfileManifest(default_profile=default_profile, profiles=profiles)


def load_profile(profile_id: str | None = None,
                 manifest_path: Path | None = None) -> NativeStackProfile:
    manifest = load_manifest(manifest_path)
    selected = profile_id or manifest.default_profile
    try:
        return manifest.profiles[selected]
    except KeyError as error:
        raise ProfileError(f"unknown native-stack profile: {selected}") from error
