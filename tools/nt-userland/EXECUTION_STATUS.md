# PE32+ Hello World execution status

## Implemented source path

The repository now has a first, deliberately restricted PE execution path:

1. `fs/binfmt_pe.c` validates AMD64 PE32+ CUI headers, section and file
   boundaries, entry-point coverage, address arithmetic, image-base bounds,
   directory ranges, page alignment, and W^X permissions.
2. Before the point of no return, malformed or unsupported images are rejected.
   The loader then uses `begin_new_exec()`, `set_personality_64bit()`,
   `setup_new_exec()`, and `setup_arg_pages()`.
3. It maps the PE headers read-only and maps each section from the executable
   file at its preferred ImageBase using `MAP_FIXED_NOREPLACE`. Anonymous,
   zero-filled mappings provide virtual section tails such as .bss.
4. It prepares a 16-byte ABI-aligned Windows-x64 entry stack with the 32-byte
   home area and transfers control using the x86 `start_thread()` path.
5. Only after the image and stack are ready does it set `PF_WINDOWS_NT`.
6. The NT syscall dispatcher implements two services for the first sample:
   - service 9, `NtWriteConsole(fd, buffer, length)`: bounded VFS write from the user buffer
     to a writable character device;
   - service 6, `NtTerminateProcess(-1, exit_code)`: terminate the current
     process and return to the parent shell.
7. `win_demo/hello_world.S` is a freestanding AMD64 entry point with no CRT,
   imports, TLS, stack frame, or unwind metadata. It writes
   `Hello, world!\r\n` to fd 1 and exits. The initramfs stages it as
   `/windows/hello_world.exe`.

## Exact supported image profile

This first loader is not a general Windows loader. It accepts only:

- AMD64 PE32+ executable images with Windows CUI subsystem.
- A fixed, page-aligned preferred ImageBase in the user address range.
- Page-aligned file layout: FileAlignment is exactly PAGE_SIZE, raw offsets and
  raw section sizes are page-aligned, and section RVAs are page-aligned.
- Image size no larger than 1 GiB.
- No imports, IAT, bound/delay imports, base relocations, TLS, x64 exception
  directory, load config/CFG, or CLR directory.
- No dynamic-base/high-entropy-VA image flag.
- No section that is both writable and executable.
- A freestanding entry point that does not require PEB, TEB, TLS, Windows DLLs,
  CRT startup, SEH/unwind support, or GUI services.

Images that do not match this profile are rejected with `-ENOEXEC`. This is
intentional: loading at a different base without applying relocations or
pretending to provide missing NT runtime structures would be unsafe.

## Build and run

On an x86-64 Linux build host with kernel build dependencies, MinGW-w64
(`x86_64-w64-mingw32-gcc`), QEMU, cpio, gzip, readelf, and a statically
linked BusyBox:

```sh
export BUSYBOX=/absolute/path/to/static/busybox
bash tools/nt-userland/build_distro.sh
```

The script builds the kernel, assembles and links the PE target, creates the
initramfs, and starts QEMU. At the BusyBox shell:

```sh
/windows/hello_world.exe
```

Expected output is `Hello, world!`, followed by a return to the shell with
exit status zero.

## Verification status

The implementation and run path are committed, but **the first execution is
not yet verified**. No kernel build, assembler/linker invocation, or QEMU boot has been run during
this work. Therefore it is not yet honest to
claim the EXE has been proven to run. The next validation step, when builds
are permitted, is to build the image and inspect the PE headers/sections if
the strict loader rejects it, then boot and run the command above.

## Deliberately not implemented

General Windows binary compatibility remains out of scope for this first
milestone: imports and DLL loading, relocations/ASLR, PEB/TEB and GS-based TLS,
SEH/unwind dispatch, Windows object handles, file I/O semantics, process/thread
creation, GUI, and broad NT syscall coverage are not implemented.
