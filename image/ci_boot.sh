#!/bin/sh
# Boot a COPY of the image in QEMU the way a PC would: OVMF with Microsoft keys and Secure Boot on,
# swtpm TPM 2.0, no network, a drive larger than the image (root grows into it). Read the console
# until the boot report appears, then check it: health passed under Secure Boot, the entry was
# blessed, and root grew. virtio disk, not emulated USB: S7 saw QEMU's usb-storage corrupt reads.
# Then the per-drive GUIDs (drive-id, L3 MUST on #41): the first boot gave the drive its own disk,
# ESP and root GUIDs; the drive boots again on them; and a PC with two fresh copies attached (every
# GUID shared) fails the health check, so that boot is never blessed and reboots into its next try.
# Usage: ci_boot.sh IMAGE [WORKDIR]. Console logs: WORKDIR/console.log, console-reboot.log,
# console-two-drives.log.
set -eu
IMG=$1; W=$(realpath -m "${2:-/var/tmp/agentos-boot}"); mkdir -p "$W"
ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm

copy() { cp --sparse=always "$IMG" "$1"; truncate -s +2G "$1"; }

# boot LOG DISK...: boot from the first disk, the others attached, until the boot report or a
# failed health check (or, with UNTIL set, that pattern) reaches the console.
boot() {
	log=$1; shift
	t=$(mktemp -d "$W/tpm.XXXXXX")
	cp /usr/share/OVMF/OVMF_VARS_4M.ms.fd "$t/vars.fd"
	swtpm socket --tpm2 --tpmstate dir="$t" --ctrl type=unixio,path="$t/sock" --daemon
	drives= i=0
	for d in "$@"; do
		i=$((i + 1)); idx=; [ $i -eq 1 ] && idx=,bootindex=1
		drives="$drives -drive if=none,id=d$i,format=raw,file=$d -device virtio-blk-pci,drive=d$i$idx"
	done
	# shellcheck disable=SC2086 # $drives is a list of QEMU arguments; the paths have no spaces.
	qemu-system-x86_64 -machine q35,smm=on -accel $ACCEL -cpu max -smp 4 -m 4096 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
		-drive if=pflash,format=raw,unit=1,file="$t/vars.fd" \
		-chardev socket,id=chrtpm,path="$t/sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
		$drives -display none -serial file:"$log" -nic none &
	QEMU=$!
	end=$(( $(date +%s) + ${TMO:-1800} ))
	while kill -0 $QEMU 2>/dev/null && [ "$(date +%s)" -lt "$end" ]; do
		grep -aq "${UNTIL:-agentos-boot:\|agentos-health: FAIL}" "$log" 2>/dev/null && break
		sleep 5
	done
	sleep 2; kill $QEMU 2>/dev/null || true; wait $QEMU 2>/dev/null || true
	echo "--- $(basename "$log")"
	grep -a "agentos-\|Secure Boot\|verity\|Failed" "$log" | tail -40 || true
}

fail=0
has() { grep -aqF "$2" "$1" && echo "ok   $2" || { echo "MISS $2"; fail=1; }; }
hasnt() { grep -aqF "$2" "$1" && { echo "UNEXPECTED $2"; fail=1; } || echo "ok   no \"$2\""; }

# GUIDs: the disk GUID and each partition's GUID, one per line, from the primary GPT.
guids() {
	python3 - "$1" <<'EOF'
import sys, uuid
with open(sys.argv[1], "rb") as f:
    f.seek(512); h = f.read(92)
    print("disk", uuid.UUID(bytes_le=h[56:72]))
    lba, n, size = int.from_bytes(h[72:80], "little"), int.from_bytes(h[80:84], "little"), int.from_bytes(h[84:88], "little")
    f.seek(lba * 512); t = f.read(n * size)
for i in range(n):
    e = t[i * size:(i + 1) * size]
    if e[:16] != bytes(16):
        print(i + 1, uuid.UUID(bytes_le=e[16:32]), e[56:128].decode("utf-16le").rstrip("\0"))
EOF
}

D=$W/disk.raw
copy "$D"
before=$(stat -c %s "$IMG")
boot "$W/console.log" "$D"
for want in "agentos-health: PASS secure_boot=on usr=verity" "agentos-boot: bless=good" "agentos-drive-id: assigned"; do
	has "$W/console.log" "$want"
done
# Root started at its 1G minimum inside an image of $before bytes; the drive gained 2G.
root=$(grep -ao "agentos-boot: .*root_bytes=[0-9]*" "$W/console.log" | sed 's/.*root_bytes=//' | tail -1)
if [ -n "$root" ] && [ "$root" -gt $((2 * 1024 * 1024 * 1024)) ]; then
	echo "ok   root grew to $root bytes"
else
	echo "MISS root grew past 2 GiB (root_bytes=${root:-none}, image $before bytes)"; fail=1
fi

# The disk GUID and the ESP and root GUIDs changed (lines "disk", 1: ESP, 6: root); the /usr
# slots kept theirs (slot A's derives from its verity root hash).
guids "$IMG" >"$W/guids-image"; guids "$D" >"$W/guids-drive"
for k in disk 1 6; do
	a=$(awk -v k=$k '$1 == k { print $2 }' "$W/guids-image"); b=$(awk -v k=$k '$1 == k { print $2 }' "$W/guids-drive")
	[ -n "$b" ] && [ "$a" != "$b" ] && echo "ok   GUID $k is the drive's own" || { echo "MISS GUID $k changed ($a)"; fail=1; }
done
for k in 2 3 4 5; do
	a=$(awk -v k=$k '$1 == k { print $2 }' "$W/guids-image"); b=$(awk -v k=$k '$1 == k { print $2 }' "$W/guids-drive")
	[ "$a" = "$b" ] && echo "ok   GUID $k kept" || { echo "MISS GUID $k kept ($a -> $b)"; fail=1; }
done

# The same drive boots again on its own GUIDs (the entry is already blessed) and keeps them.
boot "$W/console-reboot.log" "$D"
has "$W/console-reboot.log" "agentos-health: PASS secure_boot=on usr=verity"
hasnt "$W/console-reboot.log" "agentos-drive-id: assigned"

# Two fresh copies on one PC: the boot drive is ambiguous, so health fails and nothing is assigned.
copy "$W/two-a.raw"; copy "$W/two-b.raw"
UNTIL="agentos-fallback:" boot "$W/console-two-drives.log" "$W/two-a.raw" "$W/two-b.raw"
has "$W/console-two-drives.log" "agentos-drive-id: FAIL 2 partitions"
has "$W/console-two-drives.log" "agentos-health: FAIL boot drive is ambiguous"
hasnt "$W/console-two-drives.log" "agentos-boot: bless=good"
hasnt "$W/console-two-drives.log" "agentos-drive-id: assigned"
# The failed check reboots into the entry's next try without anyone at the PC (UPD-1).
has "$W/console-two-drives.log" "agentos-fallback: health check failed, 2 tries left on this boot entry; rebooting"
rm -f "$W/two-a.raw" "$W/two-b.raw"
exit $fail
