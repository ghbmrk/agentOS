#!/bin/sh
# Stand-in guest and host disk for tools/hostcheck.py (HOST-1e), until P2-1's
# image boots in CI. Writes OUTDIR/initrd.cpio and OUTDIR/windows.img.
#
# initrd.cpio: busybox and tpm2-tools. Its init prints HOSTCHECK-READY on the
#   console and runs one command line from it:
#     task PLANTS   the session's task; PLANTS is "-" (read the host disk,
#                   write nothing) or a comma list of planted writes for the
#                   harness's negative test: disk, uefi, nv, rtc
#     reboot | poweroff
# windows.img: a GPT disk laid out like a Windows install (ESP, MSR, NTFS),
#   all synthetic.
set -eu
out=${1:?usage: hostcheck_standin.sh OUTDIR}
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

root=$tmp/root
mkdir -p "$root/bin" "$root/dev" "$root/proc" "$root/sys" "$root/tmp" "$root/usr/bin"
cp "$(command -v busybox)" "$root/bin/busybox"
for app in sh mount echo printf dd sync reboot poweroff hwclock read cat sleep ln mkdir; do
	ln -s busybox "$root/bin/$app"
done
tpm2=$(readlink -f "$(command -v tpm2)")
cp "$tpm2" "$root/usr/bin/tpm2"
for t in nvdefine nvwrite; do ln -s tpm2 "$root/usr/bin/tpm2_$t"; done
tcti=/usr/lib/x86_64-linux-gnu/libtss2-tcti-device.so.0  # dlopened by name, so ldd misses it
libs=$( (ldd "$tpm2"; ldd "$tcti") | awk '/=> \//{print $3} /^\t\//{print $1}' | sort -u)
for lib in $libs "$tcti"; do
	mkdir -p "$root$(dirname "$lib")"
	cp -L "$lib" "$root$lib"
done

cat >"$root/init" <<'EOF'
#!/bin/sh
export PATH=/bin:/usr/bin TPM2TOOLS_TCTI=device:/dev/tpmrm0
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t efivarfs efivarfs /sys/firmware/efi/efivars
plant() {
	case $1 in
	disk) printf 'HOSTCHECK-SYNTHETIC-CANARY' | dd of=/dev/vda bs=512 seek=4096 conv=fsync 2>/dev/null ;;
	uefi) printf '\007\000\000\000HOSTCHECK' |
		dd of=/sys/firmware/efi/efivars/HostcheckCanary-4f1f2e3d-0000-4000-8000-686f7374636b bs=64 2>/dev/null ;;
	nv) tpm2_nvdefine 0x1500016 -C o -s 8 -a "ownerread|ownerwrite|authread|authwrite" >/dev/null &&
		printf 'HOSTCHK!' | tpm2_nvwrite 0x1500016 -C o -i - ;;
	rtc) hwclock -w -u ;;
	esac || { echo "HOSTCHECK-PLANT-FAILED $1"; ls /dev | grep -i tpm; dmesg | grep -i -E "tpm|crb" | tail -5; }
}
while :; do
	echo HOSTCHECK-READY
	read -r cmd arg || exec poweroff -f
	case $cmd in
	task)
		dd if=/dev/vda of=/dev/null bs=512 count=34 2>/dev/null
		if [ "$arg" != - ]; then
			for p in $(echo "$arg" | tr , ' '); do plant "$p"; done
		fi
		sync
		echo HOSTCHECK-DONE ;;
	reboot) sync; reboot -f ;;
	poweroff) sync; poweroff -f ;;
	esac
done
EOF
chmod +x "$root/init"
ln -s busybox "$root/bin/tr"
(cd "$root" && find . | cpio -o -H newc --quiet) >"$out/initrd.cpio"

# Host disk: 256 MiB sparse GPT, ESP 100 MiB, MSR 16 MiB, NTFS the rest.
img=$out/windows.img
rm -f "$img"
truncate -s 256M "$img"
sfdisk --quiet "$img" <<'EOF'
label: gpt
start=2048, size=204800, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="EFI system partition"
start=206848, size=32768, type=E3C9E316-0B5C-4DB8-817D-F92DF00215AE, name="Microsoft reserved partition"
start=239616, size=282624, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, name="Basic data partition"
EOF
truncate -s 100M "$tmp/esp"
mkfs.vfat -F 32 -n SYSTEM -i 484f5354 "$tmp/esp" >/dev/null
dd if="$tmp/esp" of="$img" bs=512 seek=2048 conv=notrunc,sparse status=none
ntfs_sectors=282624
truncate -s $((ntfs_sectors * 512)) "$tmp/ntfs"
mkntfs -F -Q -q -s 512 -p 239616 -H 255 -S 63 -L Windows "$tmp/ntfs" 2>/dev/null
dd if="$tmp/ntfs" of="$img" bs=512 seek=239616 conv=notrunc,sparse status=none
