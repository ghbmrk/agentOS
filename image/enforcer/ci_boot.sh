#!/bin/sh
# Boot a COPY of the enforcer image in QEMU the way the V1410 would (ENF-m, NET-2 Hardening): OVMF
# with Microsoft keys and Secure Boot on, swtpm TPM 2.0, an i6300esb hardware watchdog, a drive
# larger than the image (the state partition grows into it). The QEMU harness is the core's
# (image/ci_boot.sh), cut to what the enforcer has.
#  1. First boot: a USB stick on an xHCI controller, a network card standing in for the WAN, and a
#     credential drop-in that tries to load the simulated Wi-Fi driver (mac80211_hwsim) before the
#     self-check. The self-check passes under Secure Boot with Wi-Fi and USB storage off, the watchdog
#     armed, rp_filter read back as 0 on "all" and the card (#4810) and accept_redirects as 0 on "all",
#     "default" and the card in both families (#5164); the entry is blessed; the
#     state partition grew and is noexec; the stick stayed unauthorised; the card, standing in for
#     the WAN, has its router-advertisement handling set (#5189, ci_wan.sh).
#  2. Rollback: the drive gets a previous release's entry, and the self-check is forced to fail on
#     counted boots. The new entry's three tries run down and the previous release boots and passes.
# ENF-m-b adds the open-port set and an update whose self-check fails (briefs/ENF.md acceptance 1).
# Usage: ci_boot.sh IMAGE [WORKDIR]. Console logs: WORKDIR/console.log, console-fallback.log.
set -eu
IMG=$1; W=$(realpath -m "${2:-/var/tmp/enforcer-boot}"); mkdir -p "$W"
HERE=$(dirname "$(realpath "$0")")
ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm

copy() { cp --sparse=always "$IMG" "$1"; truncate -s +2G "$1"; }
smbios_cred() { printf ' -smbios type=11,value=io.systemd.credential.binary:%s=%s' "$1" "$(printf '%b' "$2" | base64 -w0)"; }

# boot LOG DISK: boot until the boot report or (without UNTIL) a failed self-check reaches the console.
boot() {
	log=$1; disk=$2
	t=$(mktemp -d "$W/tpm.XXXXXX")
	cp /usr/share/OVMF/OVMF_VARS_4M.ms.fd "$t/vars.fd"
	swtpm socket --tpm2 --tpmstate dir="$t" --ctrl type=unixio,path="$t/sock" --daemon
	# shellcheck disable=SC2086 # $EXTRA is a list of QEMU arguments without spaces.
	qemu-system-x86_64 -machine q35,smm=on -accel $ACCEL -cpu max -smp 2 -m 2048 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
		-drive if=pflash,format=raw,unit=1,file="$t/vars.fd" \
		-chardev socket,id=chrtpm,path="$t/sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
		-device i6300esb -action watchdog=reset \
		-drive if=none,id=d1,format=raw,file="$disk" -device virtio-blk-pci,drive=d1,bootindex=1 \
		-display none -serial file:"$log" -nic none ${EXTRA:-} &
	QEMU=$!
	end=$(( $(date +%s) + ${TMO:-1200} ))
	while kill -0 $QEMU 2>/dev/null && [ "$(date +%s)" -lt "$end" ]; do
		grep -aq "${UNTIL:-enforcer-boot:\|enforcer-health: FAIL}" "$log" 2>/dev/null && break
		sleep 5
	done
	sleep 2; kill $QEMU 2>/dev/null || true; wait $QEMU 2>/dev/null || true
	rm -rf "$t"
}

# The console with control sequences and CR removed and other bytes shown as "?", each line marked
# so no guest line reads as a ci_boot line or a workflow command.
show() {
	LC_ALL=C awk -v esc="$(printf '\033')" '{
		gsub(esc "\\[[0-9;:?]*[ -/]*[@-~]", ""); gsub(/\r/, ""); gsub(/[^ -~]/, "?"); print "console| " $0 }' "$1" |
		grep -a "enforcer-\|Secure Boot\|watchdog\|usb\|Failed\|FAIL" || true
}

fail=0
has() { grep -aqF "$2" "$1" && echo "ok   $2" || { echo "MISS $2"; fail=1; }; }
hasnt() { grep -aqF "$2" "$1" && { echo "UNEXPECTED $2"; fail=1; } || echo "ok   no \"$2\""; }

# #5189, #5330 (ENF-l-21): the WAN's router-advertisement handling, checked by ci_wan.sh. Its probe
# runs before the boot report and prints what it read on the network card.
WANRA=$(sed "/^#/d" "$HERE/ci_wan.sh" | base64 -w0)
WANRA_UNIT="[Service]\nExecStartPre=-/bin/sh -c 'echo $WANRA | base64 -d | sh -s probe'\n"

# 1. First boot.
D=$W/drive.raw
copy "$D"
truncate -s 64M "$W/stick.raw"
HWSIM="[Service]\nExecStartPre=-/bin/sh -c 'modprobe mac80211_hwsim radios=1 && echo enforcer-ci: hwsim loaded || echo enforcer-ci: hwsim refused'\n"
EXTRA="-device qemu-xhci,id=xhci -drive if=none,id=stick,format=raw,file=$W/stick.raw -device usb-storage,bus=xhci.0,drive=stick \
-netdev user,id=wan,restrict=on -device virtio-net-pci,netdev=wan$(smbios_cred systemd.unit-dropin.enforcer-health.service "$HWSIM")\
$(smbios_cred systemd.unit-dropin.enforcer-boot-report.service "$WANRA_UNIT")" \
	boot "$W/console.log" "$D"
show "$W/console.log"
has "$W/console.log" "enforcer-ci: hwsim refused"
has "$W/console.log" "enforcer-health: PASS secure_boot=on usr=verity wifi=off usb_storage=off usb_default=0 dumps=off watchdog=watchdog0:"
has "$W/console.log" "enforcer-boot: bless=good"
has "$W/console.log" " root=noexec watchdog_runtime=30s usb_devices=1 usb_unauthorised=1"
hasnt "$W/console.log" "enforcer-ci: hwsim loaded"
hasnt "$W/console.log" "enforcer-health: FAIL"
# #4810: the self-check read rp_filter as 0 on "all", "default" and every interface, among them the
# card (any name but all, default and lo), so the WAN's DHCP answers reach the ruleset.
rpf=$(grep -ao 'enforcer-health: PASS .* rp_filter=0:[^ ]*' "$W/console.log" | head -n 1 | tr -d '\r' | sed 's/.* rp_filter=0://' | tr ',' '\n')
if printf '%s\n' "$rpf" | grep -qx all && printf '%s\n' "$rpf" | grep -qx default &&
	printf '%s\n' "$rpf" | grep -qvx 'all\|default\|lo'; then
	echo "ok   rp_filter 0 on $(printf '%s' "$rpf" | tr '\n' ' ')"
else
	echo "MISS rp_filter 0 on all, default and the network card (read: $(printf '%s' "$rpf" | tr '\n' ' '))"; fail=1
fi
# #5164 R3: the self-check read accept_redirects as 0 on "all" and "default" in both families and on
# the card in both, so no interface took a redirect from boot, before agentos-enforcer runs.
red=$(grep -ao 'enforcer-health: PASS .* redirects=0:[^ ]*' "$W/console.log" | head -n 1 | tr -d '\r' | sed 's/.* redirects=0://' | tr ',' '\n')
card=$(printf '%s\n' "$red" | sed -n 's#^ipv4/##p' | grep -vx 'all\|default\|lo' | head -n 1)
if [ -n "$card" ] && (for k in ipv4/all ipv4/default ipv6/all ipv6/default "ipv4/$card" "ipv6/$card"; do
	printf '%s\n' "$red" | grep -qxF "$k" || exit 1; done); then
	echo "ok   accept_redirects 0 on $(printf '%s' "$red" | tr '\n' ' ')"
else
	echo "MISS accept_redirects 0 on all, default and the network card, IPv4 and IPv6 (read: $(printf '%s' "$red" | tr '\n' ' '))"; fail=1
fi
# #5189: the WAN's router-advertisement handling is set: accept_ra=2 on it, or an IPv6 default route.
sh "$HERE/ci_wan.sh" verdict "$W/console.log" || fail=1
# The state partition grew into the drive's extra 2 GiB.
rb=$(grep -ao 'root_bytes=[0-9]*' "$W/console.log" | head -n 1 | cut -d= -f2)
[ "${rb:-0}" -gt $((2 * 1024 * 1024 * 1024)) ] && echo "ok   state partition grew ($rb bytes)" ||
	{ echo "MISS state partition grew (root_bytes=${rb:-none})"; fail=1; }
rm -f "$D" "$W/stick.raw"

# 2. Rollback. esp DISK: the ESP's byte offset (partition 1), for mtools' "-i DISK@@OFFSET".
esp() {
	python3 -I -c 'import sys
with open(sys.argv[1], "rb") as f:
    f.seek(512); h = f.read(92)
    f.seek(int.from_bytes(h[72:80], "little") * 512); e = f.read(128)
print(int.from_bytes(e[32:40], "little") * 512)' "$1"
}
entries() { mdir -b -i "$1@@$(esp "$1")" ::/loader/entries | sed 's|.*/||' | grep '\.conf$' | LC_ALL=C sort; }
F=$W/fallback.raw
copy "$F"
new=$(entries "$F")
if [ "$(echo "$new" | wc -l)" = 1 ] && echo "$new" | grep -qx 'enforcer_[0-9][0-9.]*+3\.conf'; then
	echo "ok   one counted entry $new"
else
	echo "MISS one entry enforcer_VERSION+3.conf on the ESP ($(echo "$new" | tr '\n' ' '))"; fail=1
fi
base=${new%+3.conf}
mtype -i "$F@@$(esp "$F")" "::/loader/entries/$new" | sed 's/^version .*/version 0/' >"$W/prev.conf"
mcopy -i "$F@@$(esp "$F")" "$W/prev.conf" ::/loader/entries/enforcer_0.conf
# On a counted entry the self-check fails, naming the entry; on the uncounted previous one it runs.
FORCED=$(cat <<'EOS' | base64 -w0
v=/sys/firmware/efi/efivars/LoaderBootCountPath-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
[ -e $v ] || exit 0
echo "enforcer-forced: self-check FAIL on counted entry $(cat $v | tail -c +5 | tr -d '\000' | sed 's/.*\\//')"
exit 1
EOS
)
FORCED_UNIT="[Service]\nExecStartPre=/bin/sh -c 'echo $FORCED | base64 -d | sh'\n"
EXTRA="$(smbios_cred systemd.unit-dropin.enforcer-health.service "$FORCED_UNIT")" \
	UNTIL="enforcer-boot: bless=clean\|enforcer-fallback: this boot entry is not counted\|enforcer-fallback: no tries left on this boot entry and no other release" \
	boot "$W/console-fallback.log" "$F"
show "$W/console-fallback.log"
for want in "enforcer-forced: self-check FAIL on counted entry $base+2-1.conf" \
	"enforcer-fallback: self-check failed, 2 tries left on this boot entry; rebooting" \
	"enforcer-forced: self-check FAIL on counted entry $base+1-2.conf" \
	"enforcer-fallback: self-check failed, 1 tries left on this boot entry; rebooting" \
	"enforcer-forced: self-check FAIL on counted entry $base+0-3.conf" \
	"enforcer-fallback: no tries left on this boot entry; rebooting into the previous release" \
	"enforcer-health: PASS secure_boot=on usr=verity" \
	"enforcer-boot: bless=clean"; do
	has "$W/console-fallback.log" "$want"
done
[ "$(grep -ac "enforcer-forced: " "$W/console-fallback.log")" = 3 ] && echo "ok   exactly three failed tries" ||
	{ echo "MISS exactly three failed tries"; fail=1; }
hasnt "$W/console-fallback.log" "enforcer-boot: bless=good"
got=$(entries "$F" | tr '\n' ' ')
[ "$got" = "enforcer_0.conf $base+0-3.conf " ] && echo "ok   entries $got" ||
	{ echo "MISS entries enforcer_0.conf $base+0-3.conf (got $got)"; fail=1; }
rm -f "$F" "$W/prev.conf"

[ $fail = 0 ] && echo "ci_boot: PASS" || { echo "ci_boot: FAIL"; exit 1; }
