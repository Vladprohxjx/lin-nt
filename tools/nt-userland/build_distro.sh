#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$ROOT/tools/nt-userland"
BUILD="$WORK/build"
ROOTFS="$BUILD/rootfs"
BUSYBOX="${BUSYBOX:-}"

if [[ -z "$BUSYBOX" ]]; then
    BUSYBOX="$(command -v busybox || true)"
fi

if [[ -z "$BUSYBOX" || ! -x "$BUSYBOX" ]]; then
    echo "Set BUSYBOX to a statically linked BusyBox binary." >&2
    exit 1
fi

if readelf -l "$BUSYBOX" | grep -q 'INTERP'; then
    echo "BusyBox must be statically linked: $BUSYBOX" >&2
    exit 1
fi

command -v cargo >/dev/null
command -v qemu-system-x86_64 >/dev/null
command -v cpio >/dev/null
command -v gzip >/dev/null

cd "$ROOT"

if [[ ! -f .config ]]; then
    make defconfig
fi

scripts/config --enable BINFMT_PE \
    --enable NTSYNC \
    --enable DRM \
    --enable FB \
    --enable DEVTMPFS
make olddefconfig
make -j"$(nproc)" bzImage

cd "$WORK"
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS="-C force-unwind-tables=no -C link-arg=-nostartfiles -C link-arg=-nostdlib -C link-arg=-Wl,-e,mainCRTStartup -C link-arg=-Wl,--file-alignment,4096 -C link-arg=-Wl,--section-alignment,4096 -C link-arg=-Wl,--image-base,0x140000000 -C link-arg=-Wl,--disable-dynamicbase -C link-arg=-Wl,--disable-reloc-section" \
    cargo build --release -p win_demo

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"/{bin,sbin,dev,proc,sys,tmp,windows/system32}
cp "$BUSYBOX" "$ROOTFS/bin/busybox"
chmod 0755 "$ROOTFS/bin/busybox"

for applet in sh mount mkdir echo cat ls ps dmesg; do
    ln -sf busybox "$ROOTFS/bin/$applet"
done

cp target/x86_64-pc-windows-gnu/release/ntdll.dll \
    "$ROOTFS/windows/system32/ntdll.dll"
cp target/x86_64-pc-windows-gnu/release/kernel32.dll \
    "$ROOTFS/windows/system32/kernel32.dll"
cp target/x86_64-pc-windows-gnu/release/user32.dll \
    "$ROOTFS/windows/system32/user32.dll"
cp target/x86_64-pc-windows-gnu/release/win_demo.exe \
    "$ROOTFS/windows/hello_world.exe"

cat > "$ROOTFS/init" <<'INIT'
#!/bin/sh
/bin/mount -t proc proc /proc
/bin/mount -t sysfs sysfs /sys
/bin/mount -t devtmpfs devtmpfs /dev
echo "Linux NT hybrid kernel initramfs"
echo "Try /windows/hello_world.exe for the static PE32+ smoke test."
exec /bin/sh
INIT
chmod 0755 "$ROOTFS/init"

(
    cd "$ROOTFS"
    find . -print0 | cpio --null -ov --format=newc
) | gzip -9 > "$BUILD/initramfs.cpio.gz"

qemu-system-x86_64 \
    -m 2048 \
    -kernel "$ROOT/arch/x86/boot/bzImage" \
    -initrd "$BUILD/initramfs.cpio.gz" \
    -append "console=ttyS0 rdinit=/init" \
    -nographic
