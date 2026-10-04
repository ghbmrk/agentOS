#!/bin/sh
# Boot a COPY of the image in QEMU the way a PC would: OVMF with Microsoft keys and Secure Boot on,
# swtpm TPM 2.0, until the kit powers itself off. Then read its result file and check it.
# virtio disk, not emulated USB: S7 saw QEMU's usb-storage corrupt reads (S7 surprise 2).
# Usage: ci_boot.sh IMAGE [WORKDIR]
set -e
IMG=$1; W=$(realpath -m "${2:-/var/tmp/tk-boot}"); mkdir -p "$W/tpm"
cp --sparse=always "$IMG" "$W/disk.raw"
cp /usr/share/OVMF/OVMF_VARS_4M.ms.fd "$W/vars.fd"
swtpm socket --tpm2 --tpmstate dir="$W/tpm" --ctrl type=unixio,path="$W/tpm/sock" --daemon
ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm
timeout ${TMO:-3000} qemu-system-x86_64 -machine q35,smm=on -accel $ACCEL -cpu max -smp 4 -m 4096 \
  -global driver=cfi.pflash01,property=secure,value=on \
  -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
  -drive if=pflash,format=raw,unit=1,file="$W/vars.fd" \
  -chardev socket,id=chrtpm,path="$W/tpm/sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
  -drive if=none,id=d,format=raw,file="$W/disk.raw" -device virtio-blk-pci,drive=d,bootindex=1 \
  -nographic -serial mon:stdio -nic none > "$W/console.log" 2>&1 < /dev/null || echo "qemu exit=$?"
grep -a "TESTKIT\|Secure boot\|systemd-boot\|verity" "$W/console.log" | tail -60 || true
OFF=$(sfdisk -J "$W/disk.raw" | python3 -c "import json,sys; t=json.load(sys.stdin)['partitiontable']; \
print(next(p['start'] for p in t['partitions'] if p.get('name')=='TESTKIT')*512)")
rm -rf "$W/results"; mcopy -s -i "$W/disk.raw@@$OFF" ::/results "$W/results"
echo "---- result files"; for f in "$W"/results/*; do echo "== $f"; cat "$f"; done
R=$(ls "$W"/results/*.txt | head -1)
fail=0
for want in "secure_boot: SecureBoot enabled" "loader: systemd-boot" "usr_read_verify: PASS" "rollback: PASS" \
            "blessed: good entry blessed: yes" "found_root_via_gpt_auto: yes" "done: powering off"; do
  grep -qF "$want" "$R" && echo "ok   $want" || { echo "MISS $want"; fail=1; }
done
exit $fail
