#!/bin/sh
# Reproduce S7 candidate A end to end on an Ubuntu 24.04 x86-64 machine (root; KVM optional).
# Needs: qemu-system-x86 ovmf swtpm systemd-boot kmod cpio zstd e2fsprogs dosfstools mtools erofs-utils, and mkosi v24.3
# (Ubuntu's packaged mkosi 20.2 fails on noble's t64 package renames).
set -e
HERE=$(cd "$(dirname "$0")" && pwd); export WORK=${WORK:-/var/tmp/s7}; mkdir -p "$WORK"
MKOSI=${MKOSI:-mkosi}
for v in 1 2; do
  ( cd "$HERE" && time $MKOSI -C mkosi -f --image-version $v build )
  mkdir -p "$WORK/out_v$v" && mv "$HERE"/mkosi/agentos_$v* "$WORK/out_v$v/"
done
# Offline update drive (DEP-4): plain ext4 labelled S7UPD holding the v2 /usr and its verity tree.
truncate -s 1300M "$WORK/upd.img"; mkfs.ext4 -q -F -L S7UPD "$WORK/upd.img"
mkdir -p "$WORK/m"; mount "$WORK/upd.img" "$WORK/m"
cp "$WORK"/out_v2/agentos_2.usr.raw "$WORK"/out_v2/agentos_2.usr-verity.raw "$WORK/m/"; umount "$WORK/m"
cp "$WORK/out_v1/agentos_1.raw" "$WORK/disk.raw"
# 1) USB boot under Secure Boot with Microsoft keys (QEMU usb-storage on xHCI).
"$HERE/boot.sh" "$WORK/disk.raw" "$WORK/boot-usb.log" || true
# 2) Same disk on virtio, with the update drive attached: probe + offline A/B update.
STICKDEV="-device virtio-blk-pci,drive=stick,bootindex=1" \
EXTRA="-drive if=none,id=upd,format=raw,file=$WORK/upd.img -device virtio-blk-pci,drive=upd" \
  "$HERE/boot.sh" "$WORK/disk.raw" "$WORK/boot-update.log" || true
python3 "$HERE/check_boot.py" "$WORK/boot-update.log"
