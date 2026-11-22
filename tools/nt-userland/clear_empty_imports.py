#!/usr/bin/env python3
"""Clear MinGW's empty PE import-directory descriptor; reject real imports."""
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = bytearray(path.read_bytes())

def u16(off):
    return struct.unpack_from("<H", data, off)[0]

def u32(off):
    return struct.unpack_from("<I", data, off)[0]

pe = u32(0x3c)
assert data[pe:pe + 4] == b"PE\0\0", "not a PE image"
coff = pe + 4
nsects = u16(coff + 2)
optsz = u16(coff + 16)
opt = coff + 20
assert u16(opt) == 0x20b, "expected PE32+"
if u32(opt + 108) <= 1:
    print("No import directory.")
    raise SystemExit(0)

directory = opt + 112 + 8
rva, size = struct.unpack_from("<II", data, directory)
if rva == 0 and size == 0:
    print("Import directory already empty.")
    raise SystemExit(0)
assert rva and size, "malformed import directory"

sections = opt + optsz
fileoff = None
for i in range(nsects):
    off = sections + i * 40
    vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
    if va <= rva < va + max(vsize, rawsize):
        delta = rva - va
        assert delta + size <= rawsize, "import directory extends beyond section data"
        fileoff = rawptr + delta
        break
assert fileoff is not None, "import directory RVA is unmapped"
assert data[fileoff:fileoff + size] == bytes(size), "real imports found; refusing to patch"

data[directory:directory + 8] = bytes(8)
path.write_bytes(data)
print("Removed empty import-directory entry.")
