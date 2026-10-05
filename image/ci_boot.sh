#!/bin/sh
# Boot a COPY of the image in QEMU the way a PC would: OVMF with Microsoft keys and Secure Boot on,
# swtpm TPM 2.0, no network, a drive larger than the image (root grows into it). Read the console
# until the boot report appears, then check it: health passed under Secure Boot, the entry was
# blessed, and root grew. virtio disk, not emulated USB: S7 saw QEMU's usb-storage corrupt reads.
# Usage: ci_boot.sh IMAGE [WORKDIR]
set -eu
IMG=$1; W=$(realpath -m "${2:-/var/tmp/agentos-boot}"); mkdir -p "$W/tpm"
cp --sparse=always "$IMG" "$W/disk.raw"
before=$(stat -c %s "$W/disk.raw")
truncate -s +2G "$W/disk.raw"
cp /usr/share/OVMF/OVMF_VARS_4M.ms.fd "$W/vars.fd"
swtpm socket --tpm2 --tpmstate dir="$W/tpm" --ctrl type=unixio,path="$W/tpm/sock" --daemon
ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm
qemu-system-x86_64 -machine q35,smm=on -accel $ACCEL -cpu max -smp 4 -m 4096 \
	-global driver=cfi.pflash01,property=secure,value=on \
	-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
	-drive if=pflash,format=raw,unit=1,file="$W/vars.fd" \
	-chardev socket,id=chrtpm,path="$W/tpm/sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
	-drive if=none,id=d,format=raw,file="$W/disk.raw" -device virtio-blk-pci,drive=d,bootindex=1 \
	-display none -serial file:"$W/console.log" -nic none &
QEMU=$!
end=$(( $(date +%s) + ${TMO:-1800} ))
while kill -0 $QEMU 2>/dev/null && [ "$(date +%s)" -lt "$end" ]; do
	grep -aq "agentos-boot:\|agentos-health: FAIL" "$W/console.log" 2>/dev/null && break
	sleep 5
done
sleep 2; kill $QEMU 2>/dev/null || true; wait $QEMU 2>/dev/null || true
grep -a "agentos-\|Secure Boot\|verity\|Failed" "$W/console.log" | tail -40 || true
fail=0
for want in "agentos-health: PASS secure_boot=on usr=verity" "agentos-boot: bless=good"; do
	grep -aqF "$want" "$W/console.log" && echo "ok   $want" || { echo "MISS $want"; fail=1; }
done
# Root started at its 1G minimum inside an image of $before bytes; the drive gained 2G.
root=$(grep -ao "agentos-boot: .*root_bytes=[0-9]*" "$W/console.log" | sed 's/.*root_bytes=//' | tail -1)
if [ -n "$root" ] && [ "$root" -gt $((2 * 1024 * 1024 * 1024)) ]; then
	echo "ok   root grew to $root bytes"
else
	echo "MISS root grew past 2 GiB (root_bytes=${root:-none}, image $before bytes)"; fail=1
fi
exit $fail
