# PE execution bring-up: Hello World target

This document defines the first useful execution milestone for the experimental
NT personality. It is deliberately explicit about what is implemented and what
is not: the current PE handler is a validator, not an executable image loader.

## Target milestone

The first supported executable is a deliberately constrained, static,
x86-64 PE32+ console program named `hello_world.exe`:

- AMD64 PE32+ executable image (not a DLL).
- Native entry point, no CRT startup, no TLS callbacks.
- No imports, delay imports, bound imports, or forwarded exports.
- No base relocations in the first fixed-base milestone. The image must be
  loadable at its preferred ImageBase and must not collide with another VMA.
- No .NET/CLR, WOW64, GUI subsystem, SEH/unwind runtime, or Windows system DLLs.
- Uses only the project-local NT syscall ABI documented in
  `include/uapi/linux/ntsyscall.h`.
- Exits through the project's NT process-termination service once that service
  has a real implementation.

This restricted target is intentional. A static PE can prove that the kernel
can create an address space, map image sections, establish a user stack, enter
the PE entry point, dispatch an NT syscall, and return to Linux without first
implementing the Windows DLL ecosystem.

## Loader implementation gates

The PE loader must not set `PF_WINDOWS_NT` or transfer control until every
gate below succeeds. Failure before `begin_new_exec()` must leave the old
process intact. Failure after the point of no return must follow the same
fatal-exec rules as the ELF loader.

1. **Preflight validation**
   - Validate DOS/NT/COFF/PE32+ headers and all arithmetic with overflow checks.
   - Reject unsupported subsystem, DLL, CLR, TLS, exception, import and
     relocation directories for the initial static profile.
   - Validate section raw ranges, virtual ranges, permissions, entry-point
     coverage, image base, image size, and user address limits.
   - Bound all allocations by file size and a conservative image-size limit.

2. **Address-space construction**
   - Follow the established `load_elf_binary()` ordering:
     validate everything possible before `begin_new_exec()`, then call
     `begin_new_exec()`, `setup_new_exec()`, and `setup_arg_pages()`.
   - Reserve the preferred image range with a non-replacing mapping operation.
     Never silently relocate an image until relocation processing exists.
   - Map headers and sections with page-granular permissions. Do not create
     writable+executable mappings; copy file data while writable, then apply
     final protections.
   - Zero the virtual tail of each section (the PE equivalent of BSS).
   - Keep gaps unmapped where possible and reject overlapping page mappings
     whose permissions cannot be represented safely.

3. **Initial process state**
   - Build a valid, aligned x86-64 user stack and a documented initial
     argument/environment contract.
   - Supply the minimum process parameters required by the supported runtime.
   - Do not invent a Windows PEB/TEB or GS base by writing an MSR ad hoc.
     Thread-local state must be integrated with x86 context switching,
     clone, signal delivery, ptrace and arch_prctl before a TEB is exposed.
   - Set the NT task flag only after the image, stack, and runtime contract are
     fully installed.

4. **Entry and syscall path**
   - Set RIP to the validated PE AddressOfEntryPoint and RSP to the prepared
     user stack using the architecture's normal `start_thread()` path.
   - Keep the Linux syscall ABI for ordinary Linux tasks unchanged.
   - For NT tasks, dispatch only the documented project-local service table.
     Every implemented service must validate user pointers and return a
     defined NTSTATUS.

5. **Hello World output**
   - Add a narrowly scoped console-output service or a real handle-backed
     `NtWriteFile` implementation.
   - Copy user buffers with the normal uaccess helpers; never dereference
     userspace pointers directly in kernel context.
   - The first sample must not depend on ntdll/kernel32/user32 from Windows.

## Current repository state (source inspection only)

The current tree has:
- PE32+ header and section validation in `fs/binfmt_pe.c`.
- The PE handler intentionally returns `-ENOEXEC` after validation.
- NT syscall numbers and x86-64 dispatch routing.
- A syscall table whose entries all return `STATUS_NOT_IMPLEMENTED`.
- A Rust no-CRT PE entry-point scaffold, not a working Hello World program.
- A QEMU/initramfs build script that has not been run.

Therefore **the current tree cannot execute `hello_world.exe`**. The guide below
is the eventual invocation contract, not a claim that it works today.

## Build and run (once the loader milestone is implemented)

From the repository root, on an x86-64 Linux build host with the kernel build
dependencies, Rust, the `x86_64-pc-windows-gnu` Rust target, MinGW-w64,
QEMU, cpio, gzip, readelf, and a statically linked BusyBox installed:

```sh
rustup target add x86_64-pc-windows-gnu
export BUSYBOX=/absolute/path/to/static/busybox
bash tools/nt-userland/build_distro.sh
```

When QEMU reaches the BusyBox shell, the intended command is:

```sh
/windows/hello_world.exe
```

The shell's exec path must dispatch that file to `CONFIG_BINFMT_PE`. Until
the loader, entry setup, and at least one output syscall are implemented, this
command is expected to fail and must not be described as a successful test.

## Validation policy

No build, compiler, linker, or QEMU invocation is part of source-only review.
When execution testing is later authorized, the first acceptance test is:
the process reaches its PE entry point, writes exactly one
`Hello, world!\n` line through the NT ABI, exits with status zero, and does
not crash or corrupt the parent shell.
