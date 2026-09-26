#!/usr/bin/env python3
"""Verify a native-stack profile against operator-supplied local artifacts.

This command is intentionally separate from the exploit. It fingerprints an
offline laboratory or deployment bundle and never contacts the target.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from stack_profile import (
    DEFAULT_MANIFEST,
    NativeStackProfile,
    ProfileError,
    load_profile,
)


class VerificationError(RuntimeError):
    """Raised when an artifact does not match the selected profile."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_equal(label: str, actual: object, expected: object) -> None:
    if actual != expected:
        raise VerificationError(
            f"{label} mismatch: got {actual!r}, expected {expected!r}",
        )


def command(*arguments: str) -> str:
    try:
        result = subprocess.run(
            arguments,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise VerificationError(
            f"command failed: {' '.join(arguments)}: {error}",
        ) from error
    return result.stdout


def elf_type(path: Path) -> str:
    output = command("readelf", "-h", str(path))
    match = re.search(r"^\s*Type:\s+(EXEC|DYN)\b", output, re.MULTILINE)
    if match is None:
        raise VerificationError(f"cannot read ELF type from {path}")
    return f"ET_{match.group(1)}"


def elf_build_id(path: Path) -> str:
    output = command("readelf", "-n", str(path))
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", output)
    if match is None:
        raise VerificationError(f"cannot read ELF build ID from {path}")
    return match.group(1).lower()


def elf_bytes_at_virtual_address(path: Path, address: int,
                                 length: int) -> bytes:
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise VerificationError(f"{path} is not a little-endian ELF64 file")
    program_offset = struct.unpack_from("<Q", data, 32)[0]
    entry_size = struct.unpack_from("<H", data, 54)[0]
    entry_count = struct.unpack_from("<H", data, 56)[0]
    for index in range(entry_count):
        offset = program_offset + index * entry_size
        program_type = struct.unpack_from("<I", data, offset)[0]
        if program_type != 1:  # PT_LOAD
            continue
        file_offset, virtual_address = struct.unpack_from(
            "<QQ", data, offset + 8,
        )
        file_size = struct.unpack_from("<Q", data, offset + 32)[0]
        relative = address - virtual_address
        if 0 <= relative and relative + length <= file_size:
            start = file_offset + relative
            return data[start:start + length]
    raise VerificationError(
        f"virtual address {address:#x} is not file-backed in {path}",
    )


def json_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read JSON artifact {path}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"JSON artifact {path} is not an object")
    return value


def verify_elf_identity(label: str, path: Path, filename: str,
                        build_id: str, digest: str) -> None:
    require_equal(f"{label} filename", path.name, filename)
    require_equal(f"{label} build ID", elf_build_id(path), build_id)
    require_equal(f"{label} SHA-256", sha256(path), digest)


def verify_node(profile: NativeStackProfile, path: Path) -> None:
    node = profile.node
    verify_elf_identity("Node", path, node.filename, node.build_id, node.sha256)
    require_equal("Node ELF type", elf_type(path), node.elf_type)
    require_equal(
        "Node version",
        command(str(path), "--version").strip().removeprefix("v"),
        node.version,
    )


def verify_libvips(profile: NativeStackProfile, path: Path) -> None:
    libvips = profile.libvips
    verify_elf_identity(
        "libvips", path, libvips.filename, libvips.build_id, libvips.sha256,
    )
    relocations = command("readelf", "-Wr", str(path))
    matching = []
    for line in relocations.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[0].lower() == f"{libvips.memcpy_got_offset:016x}":
            matching.append(fields)
    if len(matching) != 1:
        raise VerificationError(
            "libvips memcpy relocation offset did not identify exactly one entry",
        )
    fields = matching[0]
    require_equal("libvips memcpy relocation", fields[2], libvips.memcpy_relocation)
    require_equal("libvips memcpy symbol", fields[4], libvips.memcpy_symbol)
    target = libvips.control_target
    symbols = command("readelf", "-Ws", str(path))
    target_symbols = []
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) < 8 or fields[-1].split("@", 1)[0] != target.symbol:
            continue
        if fields[3] == "FUNC" and fields[6] != "UND":
            target_symbols.append(fields)
    if len(target_symbols) != 1:
        raise VerificationError(
            "libvips control target did not identify exactly one function symbol",
        )
    require_equal(
        "libvips control-target symbol offset",
        int(target_symbols[0][1], 16),
        target.offset,
    )
    require_equal(
        f"libvips {target.symbol} bytes",
        elf_bytes_at_virtual_address(
            path, target.offset, len(target.bytes),
        ),
        target.bytes,
    )


def verify_package(path: Path, label: str, expected_name: str,
                   expected_version: str, expected_sha256: str) -> None:
    package = json_object(path)
    require_equal(f"{label} package name", package.get("name"), expected_name)
    require_equal(f"{label} package version", package.get("version"), expected_version)
    require_equal(f"{label} package.json SHA-256", sha256(path), expected_sha256)


def verify_versions(profile: NativeStackProfile, path: Path) -> None:
    versions = json_object(path)
    require_equal(
        "libvips versions.json SHA-256",
        sha256(path),
        profile.libvips.versions_manifest_sha256,
    )
    require_equal("bundled libvips version", versions.get("vips"), profile.libvips.version)
    require_equal(
        "bundled libheif version",
        versions.get(profile.libheif.versions_manifest_key),
        profile.libheif.version,
    )


def verify_glibc_version(profile: NativeStackProfile, path: Path) -> None:
    search = command("dpkg-query", "-S", str(path)).splitlines()
    package = search[0].split(": ", 1)[0]
    version = command("dpkg-query", "-W", "-f=${Version}", package).strip()
    require_equal("glibc package version", version, profile.glibc.version)


def verify(args: argparse.Namespace) -> dict[str, object]:
    profile = load_profile(args.profile, args.manifest)
    verify_node(profile, args.node)
    verify_libvips(profile, args.libvips)
    verify_elf_identity(
        "glibc", args.libc, profile.glibc.filename,
        profile.glibc.build_id, profile.glibc.sha256,
    )
    verify_glibc_version(profile, args.libc)
    verify_elf_identity(
        "libstdc++", args.libstdcxx, profile.libstdcxx.filename,
        profile.libstdcxx.build_id, profile.libstdcxx.sha256,
    )
    verify_package(
        args.next_package, "Next.js", "next", profile.next_package.version,
        profile.next_package.package_manifest_sha256,
    )
    verify_package(
        args.sharp_package, "sharp", "sharp", profile.sharp_package.version,
        profile.sharp_package.package_manifest_sha256,
    )
    verify_package(
        args.libvips_package, "libvips", profile.libvips.package,
        profile.libvips.package_version,
        profile.libvips.package_manifest_sha256,
    )
    verify_versions(profile, args.versions_json)
    return {
        "profile_id": profile.profile_id,
        "verified": True,
        "artifacts": 8,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify local artifacts against a native-stack profile",
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--profile")
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--libvips", type=Path, required=True)
    parser.add_argument("--libc", type=Path, required=True)
    parser.add_argument("--libstdcxx", type=Path, required=True)
    parser.add_argument("--next-package", type=Path, required=True)
    parser.add_argument("--sharp-package", type=Path, required=True)
    parser.add_argument("--libvips-package", type=Path, required=True)
    parser.add_argument("--versions-json", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args), indent=2, sort_keys=True))
    except (OSError, ProfileError, VerificationError) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
