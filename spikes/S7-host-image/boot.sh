#!/bin/sh
# Usage: boot.sh DISK LOG [VARS]  - boots DISK as a USB stick (xHCI) under OVMF with Microsoft keys + Secure Boot on, swtpm TPM 2.0.
DISK=$1; LOG=$2; VARS=${3:-${WORK:-/var/tmp/s7}/vars.fd}
[ -f "$VARS" ] || cp /usr/share/OVMF/OVMF_VARS_4M.ms.fd "$VARS"
mkdir -p ${WORK:-/var/tmp/s7}/tpm
swtpm socket --tpm2 --tpmstate dir=${WORK:-/var/tmp/s7}/tpm --ctrl type=unixio,path=${WORK:-/var/tmp/s7}/tpm/sock --daemon
timeout ${TMO:-900} qemu-system-x86_64 -machine q35,smm=on -accel tcg -cpu max -smp 4 -m 4096 \
  -global driver=cfi.pflash01,property=secure,value=on \
  -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
  -drive if=pflash,format=raw,unit=1,file="$VARS" \
  -chardev socket,id=chrtpm,path=${WORK:-/var/tmp/s7}/tpm/sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
  -device qemu-xhci,id=xhci -drive if=none,id=stick,format=raw,file="$DISK" ${STICKDEV:--device usb-storage,bus=xhci.0,drive=stick,bootindex=1} \
  -nographic -serial mon:stdio -nic none ${EXTRA} > "$LOG" 2>&1 < /dev/null
echo "qemu exit=$?"
