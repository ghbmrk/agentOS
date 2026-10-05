#!/bin/sh
# Boot COPIES of the image in QEMU the way a PC would: OVMF with Microsoft keys and Secure Boot on,
# swtpm TPM 2.0, no network, the boot drive larger than the image. virtio disks, not emulated USB:
# S7 saw QEMU's usb-storage corrupt reads. Three boots of one drive A, beside a second fresh copy B
# of the same image (Security MUST on #41 and I1-I2 on the plan: every drive starts with the same IDs):
#   1. A and B both fresh: the initrd prints one fixed line and powers off; neither drive written.
#   2. A as an interrupted first run leaves it (ESP and root rewritten, disk GUID still the seed's),
#      alone: the initrd finishes giving A its own IDs and restarts once; then health passes under
#      Secure Boot, the entry is blessed, root grew, and the machines volume exists (SR2-3i).
#   3. A beside fresh B again: A boots; every mounted partition is on A; A's disk and writable
#      partition IDs are not B's; B is byte for byte unchanged. Every service unit's device policy
#      is listed, and a root service with open device access must be in device-policy.txt (HW-8).
# Usage: ci_boot.sh IMAGE [WORKDIR]
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
IMG=$1; W=$(realpath -m "${2:-/var/tmp/agentos-boot}"); mkdir -p "$W/tpm"
before=$(stat -c %s "$IMG")
cp /usr/share/OVMF/OVMF_VARS_4M.ms.fd "$W/vars.fd"
swtpm socket --tpm2 --tpmstate dir="$W/tpm" --ctrl type=unixio,path="$W/tpm/sock" --daemon
ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm
fail=0
ok() { echo "ok   $*"; }
miss() { echo "MISS $*"; fail=1; }
ids() { sfdisk -J "$1" | jq -r '.partitiontable | "disk \(.id)", (.partitions[] | "\(.name // "-") \(.uuid)")'; }

# boot NAME DISK [SECOND [TIMEOUT]]: run until the boot report, a power-off, or the timeout. Console: $W/NAME.log
boot() {
	log=$W/$1.log; second=
	[ -n "${3:-}" ] && second="-drive if=none,id=b,format=raw,file=$3 -device virtio-blk-pci,drive=b,serial=AGENTOS-B"
	# shellcheck disable=SC2086
	qemu-system-x86_64 -machine q35,smm=on -accel $ACCEL -cpu max -smp 4 -m 4096 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
		-drive if=pflash,format=raw,unit=1,file="$W/vars.fd" \
		-chardev socket,id=chrtpm,path="$W/tpm/sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
		-drive if=none,id=a,format=raw,file="$2" -device virtio-blk-pci,drive=a,serial=AGENTOS-A,bootindex=1 \
		$second -display none -serial file:"$log" -nic none &
	q=$!
	end=$(( $(date +%s) + ${4:-${TMO:-1800}} ))
	while kill -0 $q 2>/dev/null && [ "$(date +%s)" -lt "$end" ]; do
		grep -aq "agentos-boot:\|agentos-health: FAIL" "$log" 2>/dev/null && break
		sleep 5
	done
	sleep 2; kill $q 2>/dev/null || true; wait $q 2>/dev/null || true
	echo "--- boot $1"
	grep -a "agentos-\|Secure Boot\|verity\|Failed" "$log" | grep -v "agentos-unit:" | tail -40 || true
}
has() { grep -aqF "$2" "$W/$1.log"; }
# Every boot: no unit ordering cycle (systemd would drop a job, perhaps the drive ID check).
nocycle() { grep -aqi "ordering cycle" "$W/$1.log" && miss "ordering cycle in boot $1" || ok "no ordering cycle in boot $1"; }

# 1. Two fresh copies: refused, one fixed line, power off, neither drive written.
cp --sparse=always "$IMG" "$W/a.raw"; cp --sparse=always "$IMG" "$W/b.raw"
a0=$(sha256sum <"$W/a.raw"); b0=$(sha256sum <"$W/b.raw")
boot 1-two-fresh "$W/a.raw" "$W/b.raw" 900
nocycle 1-two-fresh
has 1-two-fresh "agentos-drive: FAIL another drive carries this drive's IDs; unplug it and start again" &&
	ok "two drives with one ID refused" || miss "two drives with one ID refused"
has 1-two-fresh "agentos-boot:" && miss "boot 1 went on to boot" || ok "boot 1 stopped before root"
[ "$(sha256sum <"$W/a.raw")" = "$a0" ] && ok "A unchanged by the refused boot" || miss "A unchanged by the refused boot"
[ "$(sha256sum <"$W/b.raw")" = "$b0" ] && ok "B unchanged by the refused boot" || miss "B unchanged by the refused boot"

# 2. A as an interrupted first run leaves it (security I1): the ESP and root already have new
#    IDs, the disk GUID is still the seed's. Booted alone it finishes the job, restarts once, and
#    then boots healthy and blessed, with root grown and the machines volume made and mounted.
seed=$(ids "$W/a.raw" | sed -n 's/^disk //p')
esp=$(sfdisk -J "$W/a.raw" | jq -r '.partitiontable.partitions | to_entries[] | select(.value.type == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B") | .key + 1')
rootn=$(sfdisk -J "$W/a.raw" | jq -r '.partitiontable.partitions | length')
sfdisk -q --part-uuid "$W/a.raw" "$esp" "$(cat /proc/sys/kernel/random/uuid)"
sfdisk -q --part-uuid "$W/a.raw" "$rootn" "$(cat /proc/sys/kernel/random/uuid)"
truncate -s +10G "$W/a.raw"
boot 2-interrupted "$W/a.raw"
nocycle 2-interrupted
for want in "agentos-drive: fresh drive" "agentos-drive: done; restarting once" "agentos-drive: ok" \
	"agentos-machines: ok" "agentos-health: PASS secure_boot=on usr=verity" "agentos-boot: bless=good"; do
	has 2-interrupted "$want" && ok "$want" || miss "$want"
done
[ "$(ids "$W/a.raw" | sed -n 's/^disk //p')" != "$seed" ] && ok "A's disk GUID is its own" || miss "A's disk GUID is its own"
# Root started at its 1G minimum inside an image of $before bytes; the drive gained 10G, a fifth
# of it for root and the rest for the machines volume (repart.d 50-root, 60-machines).
size() { grep -ao "agentos-boot: .*$1=[0-9]*" "$W/2-interrupted.log" | sed -n "s/.*$1=\([0-9]*\).*/\1/p" | tail -1; }
root=$(size root_bytes); machines=$(size machines_bytes)
[ -n "$root" ] && [ "$root" -gt $((2 * 1024 * 1024 * 1024)) ] && ok "root grew to $root bytes" ||
	miss "root grew past 2 GiB (root_bytes=${root:-none}, image $before bytes)"
[ -n "$machines" ] && [ "$machines" -gt $((6 * 1024 * 1024 * 1024)) ] && ok "machines volume is $machines bytes" ||
	miss "machines volume past 6 GiB (machines_bytes=${machines:-none})"

# 3. A beside a fresh copy: A boots from its own partitions only, and B is untouched.
cp --sparse=always "$IMG" "$W/b.raw"
boot 3-beside-copy "$W/a.raw" "$W/b.raw"
nocycle 3-beside-copy
for want in "agentos-drive: ok" "agentos-machines: ok" "agentos-health: PASS secure_boot=on usr=verity" \
	"agentos-boot: bless=good"; do
	has 3-beside-copy "$want" && ok "$want" || miss "$want"
done
mounts=$(grep -a "agentos-mount:" "$W/3-beside-copy.log" | tr -d '\r' || true)
echo "$mounts"
[ "$(printf '%s\n' "$mounts" | grep -c "serial=AGENTOS-A")" -ge 3 ] && ok "root, /usr and machines mounted from A" ||
	miss "root, /usr and machines mounted from A"
printf '%s\n' "$mounts" | grep -v "serial=AGENTOS-A" | grep -q . && miss "a partition mounted from B" || ok "nothing mounted from B"
A=$(ids "$W/a.raw"); B=$(ids "$W/b.raw")
echo "A:"; echo "$A"; echo "B:"; echo "$B"
printf '%s\n' "$B" | awk '{ print $2 }' >"$W/b.ids"
shared=$(printf '%s\n' "$A" | grep -v "^agentos_" | awk '{ print $2 }' | grep -ixF -f "$W/b.ids" || true)
[ -z "$shared" ] && ok "A's disk and writable partition IDs differ from B's" || miss "A shares IDs with B: $shared"
[ "$(sha256sum <"$W/b.raw")" = "$b0" ] && ok "B byte for byte unchanged" || miss "B byte for byte unchanged"

# Device policy of every service unit (HW-8): a root service with open device access must be listed.
units=$(grep -a "agentos-unit:" "$W/3-beside-copy.log" | tr -d '\r' | sed 's/.*agentos-unit: //' || true)
[ -n "$units" ] && ok "$(printf '%s\n' "$units" | wc -l) service units listed" || miss "service units listed"
cp "$W/3-beside-copy.log" "$W/console.log"
printf '%s\n' "$units" >"$W/units.txt"
allowed=$(grep -v '^#' "$HERE/device-policy.txt" | awk 'NF { print $1 }')
open=$(printf '%s\n' "$units" | awk '$2 == "user=root" && $3 == "devices=auto" && $4 == "private=no" { print $1 }')
for u in $open; do
	printf '%s\n' "$allowed" | grep -qxF "$u" && echo "open (listed) $u" || miss "root service with open device access, not in device-policy.txt: $u"
done
exit $fail
