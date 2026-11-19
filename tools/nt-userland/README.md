# Experimental Linux NT userland

This workspace targets `x86_64-pc-windows-gnu` and is a bring-up scaffold for
the project-local NT ABI documented in `include/uapi/linux/ntsyscall.h`.

Crates:

- `ntdll`: minimal `NtClose`, `NtQuerySystemInformation` and
  `NtUserDrawFrame` syscall stubs.
- `kernel32`: minimal `GetCurrentProcess` and `CloseHandle` wrappers.
- `user32`: a minimal `DrawFrame` syscall wrapper.
- `win_demo`: a no-CRT PE entry-point smoke-test scaffold.

## Important limitations

The kernel dispatcher currently returns `STATUS_NOT_IMPLEMENTED` for every
service. The PE binfmt currently validates PE32+ metadata and deliberately
returns `-ENOEXEC`; it does not map or execute images. Consequently these
artifacts are ABI scaffolding only and are not runnable yet.

The ABI uses project-local service numbers, not Microsoft's Windows build-
specific syscall numbers. Do not use these DLLs with an unmodified Windows
kernel or assume binary compatibility with Windows system DLLs.

## Build and boot scaffold

Install the Rust target with `rustup target add x86_64-pc-windows-gnu`, a
MinGW-w64 linker, QEMU, cpio, gzip, and a statically linked BusyBox binary.
Then set `BUSYBOX=/absolute/path/to/busybox` and run
`bash tools/nt-userland/build_distro.sh` from the repository root.

The script is provided for later bring-up and has not been run as part of this
source-only change. It builds the kernel and Rust artifacts, creates a minimal
initramfs, and launches QEMU; it does not imply that PE execution is currently
functional.
