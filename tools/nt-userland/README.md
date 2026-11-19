# Experimental Linux NT userland

This workspace targets `x86_64-pc-windows-gnu` and the project-local NT ABI
in `include/uapi/linux/ntsyscall.h`. It is not binary-compatible with Windows.

## Current Hello World profile

The kernel now contains a deliberately constrained fixed-base PE32+ loader and
two minimal NT services used by the freestanding `hello_world.exe`:

- `NtWriteConsole`: writes up to one page to a writable character-device fd.
- `NtTerminateProcess`: exits the current process using pseudo-handle -1.
- PE loader: maps read-only headers and page-aligned sections at their preferred
  image base, maps zero-filled virtual tails, creates a Windows-x64-aligned
  entry stack, and transfers control to the PE entry point.

The executable is intentionally no-CRT and does not load Windows DLLs. It writes
`Hello, world!` to fd 1 and exits. The loader rejects imports, relocations,
TLS, exception/unwind metadata, CLR, dynamic-base images, GUI images, W+X
sections, non-page-aligned file layouts, and images larger than 1 GiB.

This is source-level implementation only: no kernel build, Rust compilation,
or QEMU execution has been performed. The first run is therefore still
unverified, and the restricted profile must not be mistaken for general
Windows application compatibility.

## Build and run

On an x86-64 Linux host, install the kernel build dependencies, Rust, the
Windows GNU Rust target, MinGW-w64, QEMU, cpio, gzip, readelf, and a statically
linked BusyBox. Then, from the repository root:

```sh
rustup target add x86_64-pc-windows-gnu
export BUSYBOX=/absolute/path/to/static/busybox
bash tools/nt-userland/build_distro.sh
```

The script builds the kernel and the PE program, creates an initramfs, and
boots QEMU. At the BusyBox shell run:

```sh
/windows/hello_world.exe
```

Expected output:

```text
Hello, world!
```

A successful run should return to the shell with exit status zero. If the
loader rejects the image, inspect `dmesg` and the PE optional header / section
alignment with `objdump -p` and `objdump -h`. The current loader intentionally
rejects most normal Windows executables.

## Other workspace crates

- `ntdll`: minimal wrappers for the project-local syscall ABI.
- `kernel32`: small `GetCurrentProcess` and `CloseHandle` wrappers.
- `user32`: experimental frame syscall wrapper.
- `win_demo`: the no-CRT Hello World PE entry point.

The DLL crates are scaffolding; the first Hello World executable has no import
table and does not depend on them.
