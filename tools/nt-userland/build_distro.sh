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

command -v readelf >/dev/null
if readelf -l "$BUSYBOX" | grep -q 'INTERP'; then
    echo "BusyBox must be statically linked: $BUSYBOX" >&2
    exit 1
fi

command -v x86_64-w64-mingw32-gcc >/dev/null
command -v python3 >/dev/null
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
    --enable DEVTMPFS \
    --enable DEVTMPFS_MOUNT \
    --enable SERIAL_8250 \
    --enable SERIAL_8250_CONSOLE
make olddefconfig
make -j"$(nproc)" bzImage

mkdir -p "$BUILD"
x86_64-w64-mingw32-gcc -c -x assembler-with-cpp \
    "$WORK/win_demo/hello_world.S" -o "$BUILD/hello_world.o"
x86_64-w64-mingw32-gcc -nostdlib -nostartfiles \
    -Wl,-e,mainCRTStartup \
    -Wl,--subsystem,console \
    -Wl,--file-alignment,4096 \
    -Wl,--section-alignment,4096 \
    -Wl,--image-base,0x140000000 \
    -Wl,--disable-dynamicbase \
    -Wl,--disable-high-entropy-va \
    -Wl,--disable-reloc-section \
    -Wl,--no-seh \
    -Wl,--no-insert-timestamp \
    "$BUILD/hello_world.o" -o "$BUILD/hello_world.exe"
python3 "$WORK/verify_pe.py" "$BUILD/hello_world.exe"

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"/{bin,sbin,dev,proc,sys,tmp,windows}
cp "$BUSYBOX" "$ROOTFS/bin/busybox"
chmod 0755 "$ROOTFS/bin/busybox"

for applet in sh mount mkdir echo cat ls ps dmesg; do
    ln -sf busybox "$ROOTFS/bin/$applet"
done

cp "$BUILD/hello_world.exe" "$ROOTFS/windows/hello_world.exe"
chmod 0755 "$ROOTFS/windows/hello_world.exe"

cat > "$ROOTFS/init" <<'INIT'
#!/bin/sh
/bin/mount -t proc proc /proc
/bin/mount -t sysfs sysfs /sys
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
