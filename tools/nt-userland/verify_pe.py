#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate the exact PE32+ profile accepted by fs/binfmt_pe.c."""

import struct
import sys
from pathlib import Path

PAGE = 4096
MAX_IMAGE = 1 << 30
IMAGE_BASE = 0x140000000
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_DLL = 0x2000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
UNSUPPORTED_DIRS = {1, 3, 5, 9, 10, 11, 12, 13, 14}


def fail(message):
    raise SystemExit(f"PE profile check failed: {message}")


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def main(path):
    data = Path(path).read_bytes()
    size = len(data)
    if size < 0x40 or data[:2] != b"MZ":
        fail("missing DOS MZ header")

    pe_offset = u32(data, 0x3c)
    if pe_offset < 0x40 or pe_offset + 24 > size:
        fail("invalid PE header offset")
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        fail("missing PE signature")

    coff = pe_offset + 4
    machine = u16(data, coff)
    section_count = u16(data, coff + 2)
    optional_size = u16(data, coff + 16)
    characteristics = u16(data, coff + 18)
    if machine != 0x8664:
        fail(f"machine is 0x{machine:04x}, expected AMD64")
    if not (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE):
        fail("COFF header is not marked executable")
    if characteristics & IMAGE_FILE_DLL:
        fail("image is marked as a DLL")
    if not 1 <= section_count <= 96:
        fail(f"unsupported section count: {section_count}")

    optional = coff + 20
    if optional_size < 112 or optional + optional_size > size:
        fail("truncated PE32+ optional header")
    if u16(data, optional) != 0x20b:
        fail("optional header is not PE32+")
    entry = u32(data, optional + 16)
    image_base = u64(data, optional + 24)
    section_align = u32(data, optional + 32)
    file_align = u32(data, optional + 36)
    image_size = u32(data, optional + 56)
    headers_size = u32(data, optional + 60)
    subsystem = u16(data, optional + 68)
    dll_chars = u16(data, optional + 70)
    directory_count = u32(data, optional + 108)

    if subsystem != 3:
        fail(f"subsystem is {subsystem}, expected Windows CUI (3)")
    if image_base != IMAGE_BASE or image_base % 0x10000:
        fail(f"ImageBase is 0x{image_base:x}, expected 0x{IMAGE_BASE:x}")
    if dll_chars & (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA):
        fail("dynamic-base or high-entropy-VA flag is set")
    if not (PAGE <= section_align <= 0x200000):
        fail("unsupported SectionAlignment")
    if section_align & (section_align - 1) or section_align % PAGE:
        fail("SectionAlignment must be a page-aligned power of two")
    if file_align != PAGE or section_align < file_align:
        fail("FileAlignment must equal PAGE_SIZE and not exceed SectionAlignment")
    if not image_size or image_size > MAX_IMAGE or image_size % section_align:
        fail("SizeOfImage is invalid or exceeds 1 GiB")
    if not headers_size or headers_size > image_size or headers_size % PAGE:
        fail("SizeOfHeaders must be page-aligned and inside the image")
    if not entry or entry >= image_size:
        fail("AddressOfEntryPoint is outside the image")

    section_table = optional + optional_size
    section_table_end = section_table + section_count * 40
    if section_table_end > size or section_table_end > headers_size:
        fail("section table is outside the file headers")

    if directory_count > 16 or 112 + directory_count * 8 > optional_size:
        fail("invalid data-directory count")
    for index in range(directory_count):
        rva, length = struct.unpack_from("<II", data, optional + 112 + index * 8)
        if not rva and not length:
            continue
        if not rva or not length:
            fail(f"data directory {index} has only one nonzero field")
        if index in UNSUPPORTED_DIRS:
            fail(f"unsupported data directory {index} is present")
        if index == 4:  # certificate table uses a file offset
            if rva + length > size:
                fail("certificate table extends past the file")
        elif rva + length > image_size:
            fail(f"data directory {index} extends past the image")

    sections = []
    entry_executable = False
    for index in range(section_count):
        off = section_table + index * 40
        virtual_size = u32(data, off + 8)
        virtual_address = u32(data, off + 12)
        raw_size = u32(data, off + 16)
        raw_offset = u32(data, off + 20)
        flags = u32(data, off + 36)
        extent = max(virtual_size, raw_size)
        if not extent:
            continue

        mapped_extent = align_up(extent, section_align)
        virtual_end = virtual_address + mapped_extent
        if virtual_end > image_size or virtual_address < headers_size:
            fail(f"section {index} extends outside the image")
        if virtual_address % section_align or virtual_address % PAGE:
            fail(f"section {index} RVA is not page-aligned")
        if raw_size:
            if raw_offset < headers_size or raw_offset % PAGE or raw_size % PAGE:
                fail(f"section {index} raw data is not page-aligned")
            if raw_offset + raw_size > size:
                fail(f"section {index} raw data extends past the file")
        if flags & IMAGE_SCN_MEM_WRITE and flags & IMAGE_SCN_MEM_EXECUTE:
            fail(f"section {index} is writable and executable")
        if flags & IMAGE_SCN_MEM_EXECUTE:
            if virtual_address <= entry < virtual_address + extent:
                entry_executable = True

        for prev_start, prev_end, prev_raw_start, prev_raw_end in sections:
            if virtual_address < prev_end and prev_start < virtual_end:
                fail(f"section {index} overlaps another virtual section")
            if raw_size and prev_raw_end > prev_raw_start:
                if raw_offset < prev_raw_end and prev_raw_start < raw_offset + raw_size:
                    fail(f"section {index} overlaps another raw section")
        sections.append((virtual_address, virtual_end,
                         raw_offset, raw_offset + raw_size if raw_size else raw_offset))

    if not entry_executable:
        fail("entry point is not inside an executable section")

    print("PE32+ image matches the restricted Linux NT loader profile")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} hello_world.exe")
    main(sys.argv[1])
