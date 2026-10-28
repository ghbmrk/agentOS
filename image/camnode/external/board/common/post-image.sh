#!/usr/bin/env bash
# Post-image (both boards): the slot image and the factory disk (CAM-node part c;
# briefs/CAM-node.md, design points 3 and 5; ASSUMPTIONS CAM-image-1 to -4).
#
# A slot is one partition, written whole by an update (agentos-camnode's Stage) and hashed
# whole by the manifest:
#
#   [0, 128 MiB)          the boot FAT the bootloader reads: boot.img (the signed boot image:
#                         kernel, device tree, firmware, initramfs, config.txt, cmdline.txt),
#                         boot.sig when the release signer made one, and config.txt asking for
#                         the boot image
#   [128 MiB, +root)      the erofs root
#   [after the root, ...) its verity hash tree (no superblock)
#
# cmdline.txt inside boot.img names the root's offset and length, the tree's offset, the root
# hash and the salt, so the signature over boot.img covers the root too. The factory disk is
# MBR: 1 the boot selector (autoboot.txt), 2 slot A (this slot), 3 slot B (empty), 4 the data
# partition (empty ext4). Outputs, in BINARIES_DIR: camnode-<board>.disk.img,
# camnode-<board>.slot.img, camnode-<board>.slot.json, camnode-<board>.boot.img (for the
# release signer) and SHA256SUMS.
set -euo pipefail
BIN=$1 BOARD=$2
: "${SOURCE_DATE_EPOCH:?Buildroot exports SOURCE_DATE_EPOCH (BR2_REPRODUCIBLE)}"
VERSION=${CAMNODE_VERSION:-0}
MiB=$((1024 * 1024))
FAT=$((128 * MiB))        # the slot's boot FAT
SLOT=$((512 * MiB))       # each slot partition
SELECTOR=$((16 * MiB))    # partition 1
DATA=$((64 * MiB))        # partition 4
export MTOOLS_SKIP_CHECK=1

W=$BIN/camnode-work
rm -rf "$W" && mkdir -p "$W/bootimg" "$W/slotfat"

ROOT=$BIN/rootfs.erofs
ROOT_LEN=$(stat -c %s "$ROOT")
[ $((ROOT_LEN % 4096)) -eq 0 ] || { echo "post-image: erofs size $ROOT_LEN is not whole 4 KiB blocks" >&2; exit 1; }
SALT=$(sha256sum "$ROOT" | cut -d' ' -f1)
veritysetup format --hash=sha256 --data-block-size=4096 --hash-block-size=4096 --no-superblock \
	--salt="$SALT" "$ROOT" "$W/root.verity" > "$W/verity.txt"
ROOTHASH=$(awk '/^Root hash:/ {print $3}' "$W/verity.txt")
[ ${#ROOTHASH} -eq 64 ] || { echo "post-image: no root hash from veritysetup" >&2; exit 1; }
veritysetup verify --no-superblock --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
	--salt="$SALT" "$ROOT" "$W/root.verity" "$ROOTHASH"
ROOT_OFF=$FAT
HASH_OFF=$((ROOT_OFF + ROOT_LEN))
HASH_LEN=$(stat -c %s "$W/root.verity")
SLOT_LEN=$(( (HASH_OFF + HASH_LEN + 4095) / 4096 * 4096 ))
[ "$SLOT_LEN" -le "$SLOT" ] || { echo "post-image: slot image $SLOT_LEN B is over the $SLOT B slot" >&2; exit 1; }
ARGS="camnode.root=$ROOT_OFF:$ROOT_LEN camnode.hash=$HASH_OFF camnode.roothash=$ROOTHASH camnode.salt=$SALT"

# The boot image's contents, per board.
case $BOARD in
qemu)
	cp "$BIN/Image" "$W/bootimg/Image"
	printf 'ro panic=5 console=ttyAMA0 camnode.disk=vda %s\n' "$ARGS" > "$W/bootimg/cmdline.txt"
	printf 'kernel=Image\ninitramfs camnode-initramfs.cpio followkernel\n' > "$W/bootimg/config.txt"
	;;
cm4)
	FW=$BIN/rpi-firmware
	cp "$BIN/Image" "$W/bootimg/Image"
	cp "$BIN/bcm2711-rpi-cm4.dtb" "$FW/start4.elf" "$FW/fixup4.dat" "$W/bootimg/"
	cp "$BR2_EXTERNAL_CAMNODE_PATH/board/cm4/config.txt" "$W/bootimg/config.txt"
	# No console: no console= on the command line, and enable_uart=0 in config.txt.
	printf 'ro panic=5 quiet loglevel=0 camnode.disk=mmcblk0 %s\n' "$ARGS" > "$W/bootimg/cmdline.txt"
	mkdir -p "$W/bootimg/overlays"
	for o in $(sed -n 's/^dtoverlay=\([^,]*\).*/\1/p' "$W/bootimg/config.txt" | sort -u); do
		cp "$FW/overlays/$o.dtbo" "$W/bootimg/overlays/"
	done
	[ -f "$FW/overlays/overlay_map.dtb" ] && cp "$FW/overlays/overlay_map.dtb" "$W/bootimg/overlays/"
	;;
*)
	echo "post-image: unknown board $BOARD" >&2
	exit 1
	;;
esac
cp "$BIN/camnode-initramfs.cpio" "$W/bootimg/camnode-initramfs.cpio"

# fat DIR IMAGE SIZE LABEL: a FAT image of SIZE bytes holding DIR's files, with times and the
# volume ID fixed, so the same inputs give the same bytes.
fat() {
	local dir=$1 img=$2 size=$3 label=$4
	rm -f "$img"
	find "$dir" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
	mkfs.fat --invariant -i 0ca3e0de -n "$label" -C "$img" $((size / 1024)) > /dev/null
	(cd "$dir" && find . -mindepth 1 -maxdepth 1 | LC_ALL=C sort | while read -r f; do
		mcopy -s -m -p -i "$img" "$f" ::
	done)
}

BOOTIMG_LEN=$(du -sb --apparent-size "$W/bootimg" | cut -f1)
BOOTIMG_LEN=$(( (BOOTIMG_LEN * 12 / 10 + 4 * MiB + MiB - 1) / MiB * MiB ))
fat "$W/bootimg" "$BIN/camnode-$BOARD.boot.img" "$BOOTIMG_LEN" CAMBOOT

# The slot's boot FAT. The release signer's boot.sig over boot.img goes beside it when
# CAMNODE_BOOT_SIG names one (the board's secure boot checks it, part d); an unsigned build
# boots only on a board whose key is not fused.
cp "$BIN/camnode-$BOARD.boot.img" "$W/slotfat/boot.img"
printf 'boot_ramdisk=1\n' > "$W/slotfat/config.txt"
if [ -n "${CAMNODE_BOOT_SIG:-}" ]; then
	cp "$CAMNODE_BOOT_SIG" "$W/slotfat/boot.sig"
fi
fat "$W/slotfat" "$W/slotfat.img" "$FAT" CAMSLOT

SLOTIMG=$BIN/camnode-$BOARD.slot.img
rm -f "$SLOTIMG"
cp "$W/slotfat.img" "$SLOTIMG"
dd if="$ROOT" of="$SLOTIMG" bs=1M seek=$((ROOT_OFF / MiB)) conv=notrunc status=none
dd if="$W/root.verity" of="$SLOTIMG" bs=4096 seek=$((HASH_OFF / 4096)) conv=notrunc status=none
truncate -s "$SLOT_LEN" "$SLOTIMG"
SLOT_SHA=$(sha256sum "$SLOTIMG" | cut -d' ' -f1)
cat > "$BIN/camnode-$BOARD.slot.json" <<EOF
{"board": "$BOARD", "version": $VERSION, "size": $SLOT_LEN, "sha256": "$SLOT_SHA", "roothash": "$ROOTHASH", "salt": "$SALT", "root_offset": $ROOT_OFF, "root_length": $ROOT_LEN, "hash_offset": $HASH_OFF, "signed": $([ -n "${CAMNODE_BOOT_SIG:-}" ] && echo true || echo false)}
EOF

# The boot selector: slot A by default, slot B as the one-shot (camnode ASSUMPTIONS CAM-bin-2).
mkdir -p "$W/selector"
printf '[all]\ntryboot_a_b=1\nboot_partition=2\n[tryboot]\nboot_partition=3\n' > "$W/selector/autoboot.txt"
fat "$W/selector" "$W/selector.img" "$SELECTOR" CAMSEL

# The data partition: empty ext4, its UUID and hash seed fixed. agentos-camnode's tmpfiles
# make its two directories at the first boot; nothing on it is per-install until then (HW-1).
rm -f "$W/data.ext4"
E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH mkfs.ext4 -q -L camdata -U 2f0b3c1e-6c1d-4f5e-9a39-0ca3e0de0004 \
	-E root_owner=0:0,hash_seed=2f0b3c1e-6c1d-4f5e-9a39-0ca3e0de0004,nodiscard -O ^metadata_csum_seed \
	"$W/data.ext4" $((DATA / 1024))k

cat > "$W/genimage.cfg" <<EOF
image camnode-$BOARD.disk.img {
	hdimage {
		partition-table-type = "mbr"
		disk-signature = 0x0ca3e0de
	}
	partition selector {
		partition-type = 0x0c
		image = "$W/selector.img"
		offset = 4M
		size = $SELECTOR
	}
	partition slota {
		partition-type = 0x0c
		image = "$SLOTIMG"
		size = $SLOT
	}
	partition slotb {
		partition-type = 0x0c
		size = $SLOT
	}
	partition data {
		partition-type = 0x83
		image = "$W/data.ext4"
		size = $DATA
	}
}
EOF
rm -rf "$W/genimage-tmp"
genimage --rootpath "$W/bootimg" --tmppath "$W/genimage-tmp" --inputpath "$W" --outputpath "$BIN" \
	--config "$W/genimage.cfg"

(cd "$BIN" && sha256sum "camnode-$BOARD.disk.img" "camnode-$BOARD.slot.img" "camnode-$BOARD.boot.img" \
	"camnode-$BOARD.slot.json" > SHA256SUMS)
echo "post-image: $BOARD slot $SLOT_SHA ($SLOT_LEN B), root hash $ROOTHASH"
