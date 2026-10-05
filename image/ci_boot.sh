#!/bin/sh
# Boot COPIES of the image in QEMU the way a PC would: OVMF with Microsoft keys and Secure Boot on,
# swtpm TPM 2.0, no network, the boot drive larger than the image (root grows into it). virtio
# disks, not emulated USB: S7 saw QEMU's usb-storage corrupt reads. Three boots of one drive A,
# beside a second fresh copy B of the same image (Security MUST on #41: every drive starts with
# the same IDs):
#   1. A and B both fresh: the initrd finds two drives with A's IDs and powers off; A unchanged.
#   2. A alone: the initrd gives A its own IDs and restarts once; health passes under Secure Boot,
#      the entry is blessed, root grew.
#   3. A beside fresh B again: A boots; every mounted partition is on A; A's disk and writable
#      partition IDs are not B's; B is byte for byte unchanged. Every service unit's device policy
#      is listed, and a root service with open device access must be in device-policy.txt (HW-8).
# Usage: ci_boot.sh IMAGE [WORKDIR]
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
IMG=$1; W=$(realpath -m "${2:-/var/tmp/agentos-boot}"); mkdir -p "$W/tpm"
cp --sparse=always "$IMG" "$W/a.raw"
before=$(stat -c %s "$W/a.raw")
truncate -s +2G "$W/a.raw"
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

# 1. Two fresh copies: refused before anything changes.
cp --sparse=always "$IMG" "$W/b.raw"
a0=$(ids "$W/a.raw"); b0=$(sha256sum <"$W/b.raw")
boot 1-two-fresh "$W/a.raw" "$W/b.raw" 900
has 1-two-fresh "agentos-drive: FAIL 2 drives carry this drive's IDs" && ok "two drives with one ID refused" || miss "two drives with one ID refused"
has 1-two-fresh "agentos-boot:" && miss "boot 1 went on to boot" || ok "boot 1 stopped before root"
[ "$(ids "$W/a.raw")" = "$a0" ] && ok "A unchanged by the refused boot" || miss "A unchanged by the refused boot"

# 2. A alone: its own IDs, one restart, then a healthy, blessed boot with root grown.
boot 2-first "$W/a.raw"
for want in "agentos-drive: fresh drive" "agentos-drive: done; restarting once" "agentos-drive: ok" \
	"agentos-health: PASS secure_boot=on usr=verity" "agentos-boot: bless=good"; do
	has 2-first "$want" && ok "$want" || miss "$want"
done
# Root started at its 1G minimum inside an image of $before bytes; the drive gained 2G.
root=$(grep -ao "agentos-boot: .*root_bytes=[0-9]*" "$W/2-first.log" | sed 's/.*root_bytes=//' | tail -1)
if [ -n "$root" ] && [ "$root" -gt $((2 * 1024 * 1024 * 1024)) ]; then
	ok "root grew to $root bytes"
else
	miss "root grew past 2 GiB (root_bytes=${root:-none}, image $before bytes)"
fi

# 3. A beside a fresh copy: A boots from its own partitions only, and B is untouched.
cp --sparse=always "$IMG" "$W/b.raw"
boot 3-beside-copy "$W/a.raw" "$W/b.raw"
for want in "agentos-drive: ok" "agentos-health: PASS secure_boot=on usr=verity" "agentos-boot: bless=good"; do
	has 3-beside-copy "$want" && ok "$want" || miss "$want"
done
mounts=$(grep -a "agentos-mount:" "$W/3-beside-copy.log" | tr -d '\r' || true)
echo "$mounts"
[ "$(printf '%s\n' "$mounts" | grep -c "serial=AGENTOS-A")" -ge 2 ] && ok "root and /usr mounted from A" || miss "root and /usr mounted from A"
printf '%s\n' "$mounts" | grep -v "serial=AGENTOS-A" | grep -q . && miss "a partition mounted from B" || ok "nothing mounted from B"
A=$(ids "$W/a.raw"); B=$(ids "$W/b.raw")
echo "A:"; echo "$A"; echo "B:"; echo "$B"
printf '%s\n' "$A" | grep -qx "agentos-root [0-9A-Fa-f-]*" && ok "A's root relabelled" || miss "A's root relabelled"
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
