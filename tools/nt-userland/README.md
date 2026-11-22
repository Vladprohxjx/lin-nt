# lin-nt PE demo

Build the freestanding AMD64 PE console example with the MinGW-w64 cross
compiler installed:

```sh
make -C tools/nt-userland
```

The linker profile required by the experimental fixed-base PE loader is kept
inside the Makefile. The post-link helper removes only an all-zero import
directory emitted by MinGW; it refuses to alter an image containing imports.

Install into the GNU initramfs root and rebuild the archive:

```sh
make -C tools/nt-userland install ROOTFS=../../rootfs
```

The resulting program is `rootfs/windows/hello_world.exe`. From the lin-nt
shell run `/windows/hello_world.exe`.

The sample uses lin-nt syscall IDs 9 (console write) and 6 (process exit).
