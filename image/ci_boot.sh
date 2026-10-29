#!/bin/sh
# Boot a COPY of the image in QEMU the way a PC would: OVMF with Microsoft keys and Secure Boot on,
# swtpm TPM 2.0, a drive larger than the image (root grows into it). Read the console
# until the boot report appears, then check it: health passed under Secure Boot, the entry was
# blessed, and root grew; the first boot has a cable in (QEMU user networking) and reports its
# DHCP lease (P2-1, #1416), and the host probes the inbound drop through QEMU's port forwards
# (probe_inbound.py) and, over IPv6 at the box's link-local and SLAAC addresses, through a second
# NIC whose other end is probe_lan6.py (#1457); the later boots have no network. virtio disk, not emulated USB: S7
# saw QEMU's usb-storage corrupt reads.
# Then the per-drive GUIDs (drive-id, L3 MUST on #41): the first boot gave the drive its own disk,
# ESP and root GUIDs; the drive boots again on them; and a PC with two fresh copies attached (every
# GUID shared) fails the health check, so that boot is never blessed and reboots into its next try.
# A drive holding a previous release, with health forced to fail on counted boots, runs its new
# entry's tries down to zero and falls back to the previous release (IMG-3).
# With E2E set to a directory holding a static box-e2e (broker/e2e/boxe2e), a last boot on a
# fresh copy runs the end-to-end setup run inside the box (#1688): e2e/ holds its unit and drop-ins,
# passed as SMBIOS credentials, which systemd honours only in a VM, so the image itself is unchanged.
# With SLICE set to a directory holding a static cmd/slice, a boot runs the inbox slice's eval inside
# the box (A21, #3117; see slice_run below).
# With DEVSLOT set to a directory holding the device-driver slot's boot probe, a boot runs a fixture
# driver instance under the driver template (DEVSLOT-drivers b2b-2; see below).
# With INFER set to a directory holding infer.test, a boot runs the local inference service's real
# test on the installed llama-server and model (INFER-image; see below).
# Usage: ci_boot.sh IMAGE [WORKDIR]. Console logs: WORKDIR/console.log, console-reboot.log,
# console-two-drives.log, console-fallback.log, console-slice.log, console-devslot.log, console-infer.log,
# console-e2e.log.
set -eu
HERE=$(dirname "$(realpath "$0")")
IMG=$1; W=$(realpath -m "${2:-/var/tmp/agentos-boot}"); mkdir -p "$W"
ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm

# copy FILE [SIZE]: a sparse copy of the image, grown by SIZE (default 2G) for the root to fill.
# The e2e copy is grown by 24G so vm's disk check admits its machines (image/ASSUMPTIONS.md I27).
copy() { cp --sparse=always "$IMG" "$1"; truncate -s "+${2:-2G}" "$1"; }

# Every boot orders the boot report before the serial login: getty's start resets and hangs up
# ttyS0, which discards console output still queued, and it cut or ate the report in #1705, #1746
# and #1747 (image/ASSUMPTIONS.md I24). A drop-in passed as an SMBIOS credential, like e2e/'s
# units, so the image itself is unchanged.
REPORT_FIRST=" -smbios type=11,value=io.systemd.credential.binary:systemd.unit-dropin.agentos-boot-report.service=$(printf '[Unit]\nBefore=serial-getty@ttyS0.service\n' | base64 -w0)"

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
	# 8 GiB, not 4: agentosd's pool on the guest must hold the agent and one provider worker
	# (#1896, image/ASSUMPTIONS.md I26); the hosted runner has 16 GB.
	# shellcheck disable=SC2086 # $drives, $REPORT_FIRST and $EXTRA are lists of QEMU arguments without spaces.
	qemu-system-x86_64 -machine q35,smm=on -accel $ACCEL -cpu max -smp 4 -m 8192 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd \
		-drive if=pflash,format=raw,unit=1,file="$t/vars.fd" \
		-chardev socket,id=chrtpm,path="$t/sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
		$drives -display none -serial file:"$log" -nic "${NIC:-none}" ${LAN:+-nic "$LAN"} $REPORT_FIRST ${EXTRA:-} &
	QEMU=$!
	# With PROBE6 ("HOST:PORT GUESTPORT..."), probe_lan6.py plays the router on the LAN NIC from the
	# start, so it sees the box claim its addresses; it probes once $log.go exists.
	P6=
	rm -f "$log.go"
	# shellcheck disable=SC2086 # the ports are a list of words.
	[ -z "${PROBE6:-}" ] || { python3 "$HERE/probe_lan6.py" "${PROBE6%% *}" "$log.go" ${PROBE6#* } >"$log.probe6" 2>&1 & P6=$!; }
	end=$(( $(date +%s) + ${TMO:-1800} ))
	while kill -0 $QEMU 2>/dev/null && [ "$(date +%s)" -lt "$end" ]; do
		grep -aq "${UNTIL:-agentos-boot:\|agentos-health: FAIL}" "$log" 2>/dev/null && break
		sleep 5
	done
	# With PROBE set, the booted box's ports are probed through QEMU's forwards while it runs.
	# shellcheck disable=SC2086 # $PROBE is a list of HOSTPORT:GUESTPORT words.
	[ -z "${PROBE:-}" ] || python3 "$HERE/probe_inbound.py" $PROBE >"$log.probe" 2>&1 || true
	touch "$log.go"
	[ -z "$P6" ] || wait $P6 || true
	sleep 2; kill $QEMU 2>/dev/null || true; wait $QEMU 2>/dev/null || true
	echo "--- $(basename "$log")"
	grep -a "agentos-\|Secure Boot\|verity\|Failed" "$log" | tail -40 | guest_echo || true
}

# Prints the guest console on stdin with what the console carries inside lines cut out: CSI
# sequences (":" parameters too), OSC sequences ended by BEL or ST, and CR. Any other
# non-printable byte shows as "?", the ESC of an unterminated OSC among them, so the rest of
# that line stays visible. guest_echo, e2e_console and the verdict-text check all read this.
clean() {
	LC_ALL=C awk -v esc="$(printf '\033')" '{
		gsub(esc "\\[[0-9;:?]*[ -/]*[@-~]", "")
		gsub(esc "\\][^\007" esc "]*(\007|" esc "\\\\)", "")
		gsub(/\r/, "")
		gsub(/[^ -~]/, "?")
		print
	}'
}

# Echoes guest console lines from stdin cleaned and with "console| " in front, so no guest line
# reaches the job log looking like a ci_boot line ("ci_boot:") or a workflow command ("::"); the
# verdict text itself is shown as "G1 [verdict-text]". e2e_console echoes its lines the same way.
guest_echo() {
	clean | LC_ALL=C awk '{ gsub(/G1 (NOT )?PROVEN/, "G1 [verdict-text]"); print "console| " $0 }'
}

fail=0
has() { grep -aqF "$2" "$1" && echo "ok   $2" || { echo "MISS $2"; fail=1; }; }
hasnt() { grep -aqF "$2" "$1" && { echo "UNEXPECTED $2"; fail=1; } || echo "ok   no \"$2\""; }
# disks_none LOG PREFIX: exactly one PREFIX line on the console, and it reads foreign=none, so a
# "none" line cannot hide a line that lists a host partition (IMG-1-1).
disks_none() {
	[ "$(grep -ac "$2" "$1")" = 1 ] && grep -aqE "$2 foreign=none[[:space:]]*\$" "$1" && echo "ok   $2 foreign=none" ||
		{ echo "MISS exactly one $2 line, foreign=none"; fail=1; }
}

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

# A host PC's own disk (ONB-2, HW-8): a GPT with its own ESP, a data partition, Linux swap and an
# ext4 filesystem, each holding a synthetic canary and a label (HOSTLABEL, hostlabel; partitions
# named host*) the box must not record, built without loop devices or mounts. It sits
# beside the drive on the first boot, the one that grows root and writes the drive's GUIDs, and the
# box may read its partition table and nothing else, so it must come out byte-identical.
host_disk() {
	h=$1 t=$(mktemp -d "$W/host.XXXXXX")
	rm -f "$h"; truncate -s 256M "$h"
	printf '%s\n' 'label: gpt' 'size=64M, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name=hostesp' \
		'size=64M, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7, name=hostdata' \
		'size=32M, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F, name=hostswap' \
		'type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name=hostroot' | sfdisk -q "$h"
	echo agentos-ci-canary-host-disk >"$t/canary"
	for fs in esp data; do
		mkfs.vfat -n HOSTLABEL -C "$t/$fs" 65536 >/dev/null; mcopy -i "$t/$fs" "$t/canary" ::/canary
	done
	truncate -s 32M "$t/swap"; truncate -s 64M "$t/ext4"; mkswap -q -L hostlabel "$t/swap"
	mkdir "$t/root"; cp "$t/canary" "$t/root/"; mkfs.ext4 -q -F -L hostlabel -d "$t/root" "$t/ext4"
	n=0
	sfdisk -d "$h" | sed -n 's/.*start= *\([0-9]*\).*/\1/p' | while read -r start; do
		n=$((n + 1)); f=$(echo esp data swap ext4 | cut -d' ' -f$n)
		dd if="$t/$f" of="$h" bs=512 seek="$start" conv=notrunc,sparse status=none
	done
	rm -rf "$t"
}

D=$W/disk.raw
copy "$D"
H=$W/host.raw
host_disk "$H"
host_before=$(sha256sum <"$H")
# And a host PC's USB disk, the same layout, on QEMU's xHCI (HOST-1a, hostdisk H11, H12): hidden and
# never mounted like the internal one. Only its bytes after the boot are read here, so QEMU's
# usb-storage read faults (S7, above) cannot pass or fail it.
U=$W/usb.raw
host_disk "$U"
usb_before=$(sha256sum <"$U")
USB=" -device qemu-xhci,id=xhci -drive if=none,id=usb,format=raw,file=$U -device usb-storage,bus=xhci.0,drive=usb,removable=on"
before=$(stat -c %s "$IMG")
# No unit failed, and no Wi-Fi client is on the box (D-178, #3387): systemd-networkd is the only
# network manager. The first boot runs this check as a unit passed as an SMBIOS credential, ordered before the
# boot report so its lines are on the console by then; the image itself is unchanged. The script
# rides inside the unit as base64, which holds no character systemd or the shell would expand.
units_check() {
	cat <<'EOS'
say() { echo "agentos-units: $*"; }
if [ -z "$(systemctl --failed --no-legend)" ]; then say "no failed units"; else say "FAIL failed units: $(systemctl --failed --no-legend | cut -d' ' -f1-2)"; fi
for u in NetworkManager.service wpa_supplicant.service; do systemctl cat "$u" >/dev/null 2>&1 && say "FAIL $u is installed"; done
for c in NetworkManager nmcli wpa_supplicant wpa_cli; do command -v "$c" >/dev/null 2>&1 && say "FAIL $c is installed"; done
say "Wi-Fi client checked"
systemctl is-active --quiet systemd-networkd.service && say "systemd-networkd.service active" || say "FAIL systemd-networkd.service not active"
say done
EOS
}
smbios_cred() { printf ' -smbios type=11,value=io.systemd.credential.binary:%s=%s' "$1" "$(printf '%b' "$2" | base64 -w0)"; }
UNITS_UNIT="[Unit]\nDescription=agentOS unit check (CI only)\nAfter=systemd-networkd.service\nBefore=agentos-boot-report.service serial-getty@ttyS0.service\n[Service]\nType=oneshot\nTimeoutStartSec=120\nStandardOutput=journal+console\nStandardError=journal+console\nExecStart=/bin/sh -c 'echo $(units_check | base64 -w0) | base64 -d | sh'\n"
UNITS_EXTRA="$(smbios_cred systemd.extra-unit.agentos-units-check.service "$UNITS_UNIT")"
# No code from writable storage (UPD-10): the first boot plants a copy of /usr/bin/true, mode 0755,
# in each writable mount (root and so /etc and /var/tmp, /tmp, /run, /dev/shm, /dev and the ESP, which
# gpt-auto mounts at the empty /boot when there is no XBOOTLDR) and must find every one refused, each
# but root's directories on its own mount; a transient unit with the image units' NoExecPaths=/ and ExecPaths=/usr
# finds the same in its private /tmp and /var/tmp, its StateDirectory= and a TemporaryFileSystem= it mounts
# noexec; and the weekly reboot timer is armed. Passed the same way as the unit check.
# systemd 257 leaves every namespace mount out of NoExecPaths=/'s recursive remount (apply_mounts' noexec
# deny list keeps all entries), so a unit's binds stay noexec only through the host mounts they bind, and
# its own tmpfs only through its noexec option, which mkosi.finalize requires (build (a) at 9d00e6b ran
# a planted file in a plain TemporaryFileSystem=).
noexec_check() {
	cat <<'EOS'
say() { echo "agentos-noexec: $*"; }
for d in / /var/tmp /etc /tmp /run /dev/shm /dev /boot; do
	f="${d%/}/agentos-implant"
	if cp /usr/bin/true "$f" 2>/dev/null && chmod 0755 "$f" 2>/dev/null; then
		# Each but root's own directories must be its own mount (the planted file off root's file
		# system), or its line would prove only root's noexec.
		case $d in /|/var/tmp|/etc) own=yes ;; *) mountpoint -q "$d" && [ "$(stat -c %d "$f")" != "$(stat -c %d /)" ] && own=yes || own=no ;; esac
		if [ "$own" = no ]; then say "FAIL $d is not its own mount"
		elif "$f" 2>/dev/null; then say "FAIL $d ran"; else say "$d refused"; fi
	else
		say "FAIL $d could not plant"
	fi
	rm -f "$f"
done
systemd-run --quiet --wait --pipe -p NoExecPaths=/ -p ExecPaths=/usr -p PrivateTmp=yes -p StateDirectory=agentos-noexec-probe \
	-p TemporaryFileSystem=/mnt:noexec /bin/sh -c 'for p in tmp:/tmp var-tmp:/var/tmp state:$STATE_DIRECTORY tmpfs:/mnt; do
		n=${p%%:*} f=${p#*:}/agentos-implant
		if cp /usr/bin/true "$f" && chmod 0755 "$f"; then
			if "$f"; then echo "FAIL unit $n ran"; else echo "unit $n refused"; fi
		else echo "FAIL unit $n could not plant"; fi
	done' 2>/dev/null | while read -r l; do say "$l"; done
systemctl is-active --quiet agentos-reboot.timer && say "reboot timer active" || say "FAIL reboot timer not active"
say done
EOS
}
NX_UNIT="[Unit]\nDescription=agentOS noexec check (CI only)\nBefore=agentos-boot-report.service serial-getty@ttyS0.service\n[Service]\nType=oneshot\nTimeoutStartSec=120\nStandardOutput=journal+console\nStandardError=journal+console\nExecStart=/bin/sh -c 'echo $(noexec_check | base64 -w0) | base64 -d | sh'\n"
NX_EXTRA="$(smbios_cred systemd.extra-unit.agentos-noexec-check.service "$NX_UNIT")"
# The host disks stay hidden (HW-8, HOST-1a; hostdisk ASSUMPTIONS H8, H11): the rules classed the
# root's disk as the drive and every other disk, the USB one included, as a host disk; no host node
# is ready for a mount unit or open to any uid but root, and udev recorded no label, UUID or
# partition name for one, so no /dev/disk link names it; the helper lists both disks by bus; every
# SCSI and NVMe passthrough node is root-only. Passed the same way as the unit check.
hostdisk_check() {
	cat <<'EOS'
say() { echo "agentos-hostdisk: $*"; }
prop() { udevadm info -q property -n "$1" 2>/dev/null | sed -n "s/^$2=//p"; }
n=0
until [ "$(lsblk -dnro TRAN | grep -c usb)" -ge 1 ] || [ $n -ge 60 ]; do n=$((n + 1)); sleep 1; done
udevadm settle --timeout=60
rootdisk=$(lsblk -snrpo NAME,TYPE "/dev/block/$(findmnt -rno MAJ:MIN / | tr -d ' ')" | awk '$2 == "disk" { print $1 }')
[ "$(prop "$rootdisk" AGENTOS_DISK)" = drive ] && say "drive is the root disk" ||
	say "FAIL root disk ${rootdisk:-unknown} is $(prop "$rootdisk" AGENTOS_DISK)"
nodes= bad=
for d in $(lsblk -dnrpo NAME,TYPE | awk '$2 == "disk" { print $1 }'); do
	[ "$d" = "$rootdisk" ] && continue
	for x in $(lsblk -nrpo NAME "$d"); do
		nodes="$nodes $x"
		[ "$(prop "$x" AGENTOS_DISK)" = host ] || bad="$bad $x:class=$(prop "$x" AGENTOS_DISK)"
		[ "$(prop "$x" SYSTEMD_READY)" = 0 ] || bad="$bad $x:ready"
		[ "$(stat -c '%U:%G %a' "$x")" = "root:root 600" ] || bad="$bad $x:$(stat -c '%U:%G:%a' "$x")"
		udevadm info -q property -n "$x" | grep -qE '^ID_(FS_LABEL|FS_UUID|PART_ENTRY_NAME|PART_ENTRY_UUID|PART_TABLE_UUID)=' &&
			bad="$bad $x:ids"
	done
done
[ -n "$nodes" ] && [ -z "$bad" ] && say "every host node hidden" || say "FAIL host nodes:${bad:- none found}"
links=
for l in /dev/disk/by-*/*; do
	[ -e "$l" ] || continue
	t=$(readlink -f "$l")
	for x in $nodes; do [ "$t" = "$x" ] && links="$links $l"; done
	case ${l##*/} in HOSTLABEL | hostlabel | host*) links="$links $l" ;; esac
done
[ -z "$links" ] && say "no label or link names a host disk" || say "FAIL links:$links"
buses=$(/usr/lib/agentos/agentos-hostdisk list | sed -n 's/^ *"bus": "\([a-z]*\)".*/\1/p' | sort | tr '\n' ' ')
say "host disks ${buses% }"
c=0 open=
for x in /dev/sg* /dev/bsg/* /dev/ng* /dev/nvme[0-9] /dev/nvme[0-9][0-9]; do
	[ -c "$x" ] || continue
	c=$((c + 1))
	[ "$(stat -c '%U:%G %a' "$x")" = "root:root 600" ] || open="$open $x:$(stat -c '%U:%G:%a' "$x")"
done
# At least the USB disk's own bsg node, so the line proves the 72 rule on a real udev.
if [ "$c" -lt 1 ]; then say "FAIL no passthrough node found"
elif [ -z "$open" ]; then say "passthrough nodes root-only ($c)"
else say "FAIL passthrough nodes:$open"; fi
say done
EOS
}
HD_UNIT="[Unit]\nDescription=agentOS host disk check (CI only)\nAfter=systemd-udev-trigger.service\nBefore=agentos-boot-report.service serial-getty@ttyS0.service\n[Service]\nType=oneshot\nTimeoutStartSec=180\nStandardOutput=journal+console\nStandardError=journal+console\nExecStart=/bin/sh -c 'echo $(hostdisk_check | base64 -w0) | base64 -d | sh'\n"
HD_EXTRA="$(smbios_cred systemd.extra-unit.agentos-hostdisk-check.service "$HD_UNIT")"
# One multi-user.target drop-in starts every check: systemd reads a credential name once, so a
# second systemd.unit-dropin.multi-user.target would be dropped, and its check never run (#2875).
CHECKS_WANTED="$(smbios_cred systemd.unit-dropin.multi-user.target '[Unit]\nWants=agentos-units-check.service agentos-noexec-check.service agentos-hostdisk-check.service\n')"

# Forwards from the host to box ports 22, 80, 443, 18789 and 5355 (resolved's LLMNR): each must be
# dropped (I11, I19). The owner page's 80 and 443 open only on port 1 once the page's unit names it
# (CH-9, D-178, HW12-port1-set), and with two NICs here it names none. The LAN NIC carries the same
# probe over IPv6 (#1457), where every port is dropped.
EXTRA="$UNITS_EXTRA$NX_EXTRA$HD_EXTRA$CHECKS_WANTED$USB" NIC="user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:18022-:22,hostfwd=tcp:127.0.0.1:18080-:80,hostfwd=tcp:127.0.0.1:18443-:443,hostfwd=tcp:127.0.0.1:18789-:18789,hostfwd=tcp:127.0.0.1:15355-:5355" \
	LAN="socket,model=virtio-net-pci,listen=127.0.0.1:18600" PROBE6="127.0.0.1:18600 22 80 443 18789 5355" \
	PROBE="18022:22 18080:80 18443:443 18789:18789 15355:5355" boot "$W/console.log" "$D" "$H"
for want in "agentos-health: PASS secure_boot=on usr=verity inbound=drop swap=off dumps=off forward=off hostdisk=ok" "agentos-boot: bless=good" "agentos-drive-id: assigned"; do
	has "$W/console.log" "$want"
done
for want in "agentos-hostdisk: drive is the root disk" "agentos-hostdisk: host disks usb virtio" \
	"agentos-hostdisk: every host node hidden" "agentos-hostdisk: no label or link names a host disk" \
	"agentos-hostdisk: passthrough nodes root-only" "agentos-hostdisk: done"; do
	has "$W/console.log" "$want"
done
hasnt "$W/console.log" "agentos-hostdisk: FAIL"
# No unit failed and no Wi-Fi client is on the box. The health line above still reads forward=off
# inbound=drop, and the probes below find every port dropped (DEV-2).
for want in "agentos-units: no failed units" "agentos-units: Wi-Fi client checked" \
	"agentos-units: systemd-networkd.service active" "agentos-units: done"; do
	has "$W/console.log" "$want"
done
hasnt "$W/console.log" "agentos-units: FAIL"
for d in / /var/tmp /etc /tmp /run /dev/shm /dev /boot; do
	has "$W/console.log" "agentos-noexec: $d refused"
done
for want in "agentos-noexec: unit tmp refused" "agentos-noexec: unit var-tmp refused" "agentos-noexec: unit state refused" \
	"agentos-noexec: unit tmpfs refused" "agentos-noexec: reboot timer active" "agentos-noexec: done"; do
	has "$W/console.log" "$want"
done
hasnt "$W/console.log" "agentos-noexec: FAIL"
# The host disk is not the boot drive (drive-id saw one boot partition), nothing wrote to it, and
# the guest reports no mount or swap on it (a read-only mount leaves the bytes unchanged, IMG-1-1).
[ "$(sha256sum <"$H")" = "$host_before" ] && echo "ok   host disk unchanged" || { echo "MISS host disk unchanged"; fail=1; }
[ "$(sha256sum <"$U")" = "$usb_before" ] && echo "ok   USB host disk unchanged" || { echo "MISS USB host disk unchanged"; fail=1; }
disks_none "$W/console.log" "agentos-disks:"
rm -f "$H" "$U"
# Root carries project quotas, so each agent machine writes under its own hard quota (RES-4, #1386),
# and the agentosd command systemd loaded ends -disk-quota on (flag=on).
has "$W/console.log" "agentos-quota: root=ext4 prjquota flag=on"
# The wired uplink took a lease on the first boot; the reboot, with no cable, did not wait for one.
# Positive: an interface and an address on the report's one line, so a damaged line is no lease.
lease='agentos-uplink: [a-z0-9]+ [0-9.]+/[0-9]+ agentos-boot: bless=good'
grep -aqE "$lease" "$W/console.log" && echo "ok   $lease" || { echo "MISS $lease"; fail=1; }
# The lease is 10.0.2.15, the forwards' target: a probe that never reached the box would also read
# "dropped" (#1457).
if grep -a "agentos-uplink: " "$W/console.log" | grep -qF " 10.0.2.15/"; then
	echo "ok   lease at the forwards' target 10.0.2.15"
else
	echo "MISS agentos-uplink: <if> 10.0.2.15/ (the forwards' target)"; fail=1
fi
# The host's connections through the forwards reach the box's leased address and get no answer.
# The page's ports too: this boot has two fixed NICs, so the page names no port 1 and the inbound
# table's page set stays empty (HW12-port1-set); boxe2e shows the page served through the set.
cat "$W/console.log.probe" 2>/dev/null || true
for port in 22 80 443 18789 5355; do
	has "$W/console.log.probe" "agentos-probe: $port dropped"
done
# Over IPv6 on the LAN NIC: the box answers neighbour discovery at its link-local and SLAAC
# addresses (the probe reaches it there), and no port answers at either.
cat "$W/console.log.probe6" 2>/dev/null || true
for scope in fe80 global; do
	has "$W/console.log.probe6" "agentos-probe6: $scope reachable"
	for port in 22 80 443 18789 5355; do
		has "$W/console.log.probe6" "agentos-probe6: $scope $port dropped"
	done
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
# That boot also runs the monthly restore drill end to end (#2932): with no drill on record one is
# due, so a CI-only unit starts the weekly reboot after the boot report; reboot-weekly reads all of
# /usr through verity against usrhash= and reboots in the guest, and the next healthy boot reports
# the time to a clean core. The unit is skipped once a drill is on record, so the second boot stays up.
DRILL_UNIT="[Unit]\nDescription=agentOS restore drill start (CI only)\nAfter=agentos-boot-report.service\nConditionPathExists=!/var/lib/agentos/drill/last.json\n[Service]\nType=oneshot\nExecStart=systemctl start --no-block agentos-reboot.service\n"
DRILL_EXTRA="$(smbios_cred systemd.extra-unit.agentos-drill-ci.service "$DRILL_UNIT")$(smbios_cred systemd.unit-dropin.multi-user.target '[Unit]\nWants=agentos-drill-ci.service\n')"
# The same boots enroll the keeper (STO-2c, #2905): setup's Owner Card factors, synthetic and CI's
# only, reach /run/agentos-setup (the image makes it) through a tmpfiles.extra credential, so the
# first of the two boots makes the sealed store on this QEMU's swtpm and the second, on the same
# TPM, finds it. Each time the unlock step opens the store through its tpm slot under the boot's
# PCRs, with the pins it reads from the TPM, and with none of the owner's hardware keys enrolled
# yet hands the kernel no anchors, so the kernel starts setup-only on its sockets (#2996, #3073).
KEEPER_FACTORS='f /run/agentos-setup/passphrase 0600 root root - ci-synthetic-passphrase-not-a-secret\nf /run/agentos-setup/recovery 0600 root root - 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n'
KEEPER_EXTRA="$(smbios_cred tmpfiles.extra "$KEEPER_FACTORS")"
# The drill's line comes before the boot report's (agentos-drill-report.service is ordered before it),
# so the boot runs until the second boot's keeper line.
EXTRA="$DRILL_EXTRA$KEEPER_EXTRA" UNTIL="agentos-keeper: enroll=skipped\|agentos-keeper: enroll=failed\|agentos-health: FAIL" TMO=600 boot "$W/console-reboot.log" "$D"
# The first boot staged the page authority before enrollment, which then stored it (OWN-card-flow);
# the second, with a store, staged none.
has "$W/console-reboot.log" "agentos-keeper: enroll=ran kernel=active pageca=staged"
has "$W/console-reboot.log" "agentos-keeper: enroll=skipped kernel=active pageca=skipped"
has "$W/console-reboot.log" "agentos-keeper: enroll=skipped"
# After the drill's reboot too, so the tpm slot opened again on a second boot's PCRs: the kernel runs
# only once the unlock step has opened the store and exec'd it.
LC_ALL=C awk '/agentos-reboot: drill image=verified/ { r = 1 } r && /agentos-keeper: enroll=skipped kernel=active/ { f = 1 }
	END { exit !f }' "$W/console-reboot.log" && echo "ok   agentos-unlock opened the store again after the reboot" ||
	{ echo "MISS agentos-unlock opened the store again after the reboot"; fail=1; }
# The kernel made its sockets, and no start was refused (#3073).
hasnt "$W/console-reboot.log" "listen unix /run/agentos-kernel/"
hasnt "$W/console-reboot.log" "agentos-unlock: seal:"
hasnt "$W/console-reboot.log" "agentos-keeper: enroll=failed"
hasnt "$W/console-reboot.log" "agentos-unlock: my policy key and store anchor on this PC's TPM"
has "$W/console-reboot.log" "agentos-reboot: drill image=verified"
has "$W/console-reboot.log" "agentos-drill: pass image=verified clean_core_seconds="
hasnt "$W/console-reboot.log" "agentos-drill: FAIL"
has "$W/console-reboot.log" "agentos-health: PASS secure_boot=on usr=verity"
has "$W/console-reboot.log" "agentos-quota: root=ext4 prjquota flag=on"
hasnt "$W/console-reboot.log" "agentos-drive-id: assigned"
has "$W/console-reboot.log" "agentos-uplink: none"

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

# Forced-fail fallback (UPD-1, IMG-3; REQ: UPD-1): a fresh copy whose ESP also holds a previous
# release, the same entry under version 0 and without a counter (blessed), as an updater would
# leave it. A drop-in passed as an SMBIOS credential, so the image itself is unchanged, fails the
# health check on every counted boot and passes it on an uncounted one: the new release fails
# every try, its counter runs down to zero across the reboots and it is never blessed, then the
# fallback reboots into the previous release, which passes. Each forced failure prints the entry
# it booted, so the console shows the counter at each try. The previous release has the same
# /usr (slot B holds none until an updater writes one), so this shows the boot-counting fallback,
# not a slot-B boot (image/ASSUMPTIONS.md I4).
# esp DISK: the byte offset of the ESP (partition 1), for mtools' "-i DISK@@OFFSET".
esp() {
	python3 - "$1" <<'EOF'
import sys
with open(sys.argv[1], "rb") as f:
    f.seek(512); h = f.read(92)
    f.seek(int.from_bytes(h[72:80], "little") * 512); e = f.read(128)
print(int.from_bytes(e[32:40], "little") * 512)
EOF
}
# entries DISK: the boot entry file names on the drive's ESP, sorted, one per line.
entries() { mdir -b -i "$1@@$(esp "$1")" ::/loader/entries | sed 's|.*/||' | grep '\.conf$' | LC_ALL=C sort; }
forced_fail() {
	cat <<'EOS'
# tail on the efivarfs file itself printed nothing in CI (#2800's first run); fallback's cat does read it.
v=/sys/firmware/efi/efivars/LoaderBootCountPath-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
[ -e $v ] || exit 0
echo "agentos-forced: health FAIL on counted entry $(cat $v | tail -c +5 | tr -d '\000' | sed 's/.*\\//')"
exit 1
EOS
}
F=$W/fallback.raw
copy "$F"
new=$(entries "$F")
if [ "$(echo "$new" | wc -l)" = 1 ] && echo "$new" | grep -qx 'agentos_[0-9][0-9.]*+3\.conf'; then
	echo "ok   one counted entry $new"
else
	echo "MISS one entry agentos_VERSION+3.conf on the ESP ($(echo "$new" | tr '\n' ' '))"; fail=1
fi
base=${new%+3.conf}
mtype -i "$F@@$(esp "$F")" "::/loader/entries/$new" | sed 's/^version .*/version 0/' >"$W/prev.conf"
mcopy -i "$F@@$(esp "$F")" "$W/prev.conf" ::/loader/entries/agentos_0.conf
FORCED_UNIT="[Service]\nExecStartPre=/bin/sh -c 'echo $(forced_fail | base64 -w0) | base64 -d | sh'\n"
EXTRA="$(smbios_cred systemd.unit-dropin.agentos-health.service "$FORCED_UNIT")" \
	UNTIL="agentos-boot: bless=clean\|agentos-fallback: this boot entry is not counted\|agentos-fallback: no tries left on this boot entry and no other release" \
	boot "$W/console-fallback.log" "$F"
# Three tries, each failed with the counter one lower, each followed by the fallback's reboot.
for want in "agentos-forced: health FAIL on counted entry $base+2-1.conf" \
	"agentos-fallback: health check failed, 2 tries left on this boot entry; rebooting" \
	"agentos-forced: health FAIL on counted entry $base+1-2.conf" \
	"agentos-fallback: health check failed, 1 tries left on this boot entry; rebooting" \
	"agentos-forced: health FAIL on counted entry $base+0-3.conf" \
	"agentos-fallback: no tries left on this boot entry; rebooting into the previous release"; do
	has "$W/console-fallback.log" "$want"
done
[ "$(grep -ac "agentos-forced: " "$W/console-fallback.log")" = 3 ] && echo "ok   exactly three failed tries" ||
	{ echo "MISS exactly three failed tries"; fail=1; }
# Then the previous release boots, passes and stays up; the new release was never blessed.
has "$W/console-fallback.log" "agentos-health: PASS secure_boot=on usr=verity"
has "$W/console-fallback.log" "agentos-boot: bless=clean"
hasnt "$W/console-fallback.log" "agentos-boot: bless=good"
last=$(grep -a "agentos-forced: \|agentos-health: \|agentos-boot: " "$W/console-fallback.log" | clean | tail -n 1)
case $last in
*"agentos-boot: bless=clean"*) echo "ok   the previous release's report is the last boot" ;;
*) echo "MISS the previous release's report as the last boot (last: $last)"; fail=1 ;;
esac
# On the ESP the new entry is spent and unblessed (+0-3), and the previous one is unchanged.
got=$(entries "$F" | tr '\n' ' ')
[ "$got" = "agentos_0.conf $base+0-3.conf " ] && echo "ok   entries $got" ||
	{ echo "MISS entries agentos_0.conf $base+0-3.conf (got $got)"; fail=1; }
rm -f "$F" "$W/prev.conf"

# A21 in QEMU (#3117, broker/clerk/inbox/ASSUMPTIONS.md MIG-3-1). With SLICE set to a directory
# holding a static cmd/slice, a fresh copy boots under Secure Boot and a CI-only unit, passed as an
# SMBIOS credential like the e2e units, runs the slice twice over every request slice_boot.py
# wrote, from a read-only 9p share, with no network (PrivateNetwork=yes: the one-click POSTs are
# recorded, never sent). Outcomes go to a second, writable share; the host then runs the eval
# harness over them (slice_boot.py check), so the pass is the harness's, never the guest's word.
# The unit mounts both shares and starts the run in one command, inside the mount namespace the
# main-side mask gives every agentos-* unit (agentos-.service.d/50-main-side.conf).
slice_run() {
	cat <<'EOS'
in=/run/agentos-slice/in out=/run/agentos-slice/out n=0 bad=0
for r in "$in"/req/*.json; do
	d=$(basename "$r" .json)
	for i in 1 2; do
		"$in/slice" <"$r" >"$out/$d.$i.json" 2>"$out/$d.$i.err" || { bad=$((bad + 1)); echo "agentos-slice: FAIL $d run $i"; }
	done
	n=$((n + 1))
done
echo "agentos-slice: DONE requests=$n failed=$bad"
EOS
}
if [ -n "${SLICE:-}" ]; then
	SS=$W/slice-share SO=$W/slice-out
	rm -rf "$SS" "$SO"; mkdir -p "$SS/req" "$SO"
	cp "$SLICE/slice" "$SS/slice" && echo "ok   slice binary for the slice boot" || { echo "MISS slice binary for the slice boot"; fail=1; }
	python3 -I "$HERE/slice_boot.py" requests "$SS/req" || fail=1
	slice_run >"$SS/run.sh"
	P9="trans=virtio,version=9p2000.L"
	SLICE_UNITS="$(smbios_cred systemd.extra-unit.agentos-slice.service "[Unit]\nDescription=agentOS inbox slice eval (CI only)\nAfter=systemd-tmpfiles-setup.service\nBefore=agentos-boot-report.service serial-getty@ttyS0.service\n[Service]\nType=oneshot\nTimeoutStartSec=1200\nPrivateNetwork=yes\nStandardOutput=journal+console\nStandardError=journal+console\nExecStart=/bin/sh -c 'mkdir -p /run/agentos-slice/in /run/agentos-slice/out && mount -t 9p -o $P9,ro slice /run/agentos-slice/in && mount -t 9p -o $P9 sliceout /run/agentos-slice/out && exec /bin/sh /run/agentos-slice/in/run.sh'\n")"
	SLICE_UNITS="$SLICE_UNITS$(smbios_cred systemd.unit-dropin.multi-user.target '[Unit]\nWants=agentos-slice.service\n')"
	copy "$W/slice.raw"
	TMO=2400 EXTRA="-virtfs local,path=$SS,mount_tag=slice,security_model=none,readonly=on -virtfs local,path=$SO,mount_tag=sliceout,security_model=none$SLICE_UNITS" \
		UNTIL="agentos-slice: DONE\|agentos-health: FAIL" boot "$W/console-slice.log" "$W/slice.raw"
	has "$W/console-slice.log" "agentos-slice: DONE"
	has "$W/console-slice.log" " failed=0"
	hasnt "$W/console-slice.log" "agentos-slice: FAIL"
	python3 -I "$HERE/slice_boot.py" check "$SO" || fail=1
	rm -rf "$W/slice.raw" "$SS" "$SO"
fi

# The device-driver slot's sandbox and key, in a booted image (DEVSLOT-drivers b2b-2, #3590). With
# DEVSLOT set to a directory holding static builds of broker/clerk/devslot/proc/testdata's bootdriver
# and bootprobe, a fresh copy boots with mkosi.finalize's own DRIVER_TEMPLATE rendered for the name
# "fixture", passed as SMBIOS credentials with only the binary's path changed to the read-only 9p
# share, so the image itself is unchanged. A CI-only unit (no agentos- prefix, so outside the main
# side's mask) mounts the share and runs bootprobe as root: it seals the fixture's device-key file,
# serves its key socket with the kernel's own hand-off code for the template's instances, then, as
# the host's uid, runs one operation per fresh instance. One finds socket() refused for every family,
# a root that is the empty tmpfs (/etc/passwd ENOENT), descriptor 0 /dev/null and Lend giving the
# fixture's own canary slot, in an instance started under the main side's mask (226/NAMESPACE,
# #3589); one hangs (asleep, so the Go runtime never ends it as deadlocked) and must be killed at
# the template's RuntimeMaxSec=.
if [ -n "${DEVSLOT:-}" ]; then
	DS=$W/devslot-share
	rm -rf "$DS"; mkdir -p "$DS/units"
	for b in bootdriver bootprobe; do
		cp "$DEVSLOT/$b" "$DS/$b" && echo "ok   $b for the devslot boot" || { echo "MISS $b for the devslot boot"; fail=1; }
	done
	python3 -I - "$HERE/mkosi/mkosi.finalize" "$DS/units" <<'EOP' || fail=1
import importlib.machinery, importlib.util, pathlib, sys
loader = importlib.machinery.SourceFileLoader("finalize", sys.argv[1])
check = importlib.util.module_from_spec(importlib.util.spec_from_loader("finalize", loader))
loader.exec_module(check)
for rel, text in check.driver_units("fixture").items():
    text = text.replace("/usr/lib/agentos/drivers/fixture/driver", "/run/agentos-ci-devslot/bootdriver")
    name = "dropin.conf" if rel.endswith("/90-driver.conf") else rel.rsplit("/", 1)[-1]
    pathlib.Path(sys.argv[2], name).write_text(text)
EOP
	P9="trans=virtio,version=9p2000.L"
	DCG=/agentos.slice/agentos-drivers.slice/agentos-driver-fixture@.service
	ufile() { printf ' -smbios type=11,value=io.systemd.credential.binary:%s=%s' "$1" "$(base64 -w0 "$DS/units/$2")"; }
	DS_UNITS="$(ufile sysusers.extra agentos-driver-fixture.conf)$(ufile systemd.extra-unit.agentos-driver-fixture.socket agentos-driver-fixture.socket)"
	DS_UNITS="$DS_UNITS$(ufile 'systemd.extra-unit.agentos-driver-fixture@.service' 'agentos-driver-fixture@.service')"
	DS_UNITS="$DS_UNITS$(ufile 'systemd.unit-dropin.agentos-driver-fixture@.service~90-driver' dropin.conf)"
	DS_UNITS="$DS_UNITS$(smbios_cred systemd.extra-unit.ci-devslot.service "[Unit]\nDescription=agentOS device-driver slot probe (CI only)\nWants=agentos-driver-fixture.socket\nAfter=systemd-sysusers.service systemd-tmpfiles-setup.service agentos-driver-fixture.socket\nBefore=agentos-boot-report.service serial-getty@ttyS0.service\n[Service]\nType=oneshot\nTimeoutStartSec=600\nStandardOutput=journal+console\nStandardError=journal+console\nExecStart=/bin/sh -c 'mkdir -p /run/agentos-ci-devslot && mount -t 9p -o $P9,ro devslot /run/agentos-ci-devslot && exec /run/agentos-ci-devslot/bootprobe -cgroup $DCG'\n")"
	DS_UNITS="$DS_UNITS$(smbios_cred systemd.unit-dropin.multi-user.target '[Unit]\nWants=ci-devslot.service\n')"
	copy "$W/devslot.raw"
	EXTRA="-virtfs local,path=$DS,mount_tag=devslot,security_model=none,readonly=on$DS_UNITS" \
		UNTIL="agentos-devslot: DONE\|agentos-health: FAIL" boot "$W/console-devslot.log" "$W/devslot.raw"
	grep -a "agentos-devslot:\|agentos-driver-fixture\|driver-fixture's key" "$W/console-devslot.log" | guest_echo || true
	has "$W/console-devslot.log" "agentos-devslot: DONE"
	for c in "instance started under the main side's mask" "socket() refused (inet=1 unix=1)" "opening /etc/passwd fails with ENOENT" \
		"the root is the empty tmpfs (no /etc, no /var)" \
		"descriptor 0 is /dev/null" "Lend yields the canary key and no other slot (key=1)" "a hung operation is killed at RuntimeMaxSec"; do
		has "$W/console-devslot.log" "agentos-devslot: ok   $c"
	done
	hasnt "$W/console-devslot.log" "agentos-devslot: FAIL"
	rm -rf "$W/devslot.raw" "$DS"
fi

# The local inference service's real runtime, in a booted image (INFER-image, #3655; INFER-SVC E2).
# With INFER set to a directory holding infer.test (broker/cmd/agentos-infer's tests built with the
# tags infer_real and infer_llamacpp, static), a fresh copy boots and a CI-only unit, passed as an
# SMBIOS credential, runs TestRealRuntimeEmbed from a read-only 9p share as agentos-infer, with no
# network, on the llama-server and the model the image installs: 1024 finite floats a text, the
# same across calls, and the model's hash equal to the pin in llama.pins (which agentosd.service
# passes too). The test starts the service itself, so the image's -infer stays off. Its socket
# directory goes under the host's /tmp as the service user (ASSUMPTIONS INFER-A14).
if [ -n "${INFER:-}" ]; then
	IS=$W/infer-share
	rm -rf "$IS"; mkdir -p "$IS"
	cp "$INFER/infer.test" "$IS/infer.test" && echo "ok   infer.test for the inference boot" || { echo "MISS infer.test for the inference boot"; fail=1; }
	PIN=$(sed -n 's/^embed_sha256=//p' "$HERE/../broker/cmd/agentos-infer/llama.pins")
	P9="trans=virtio,version=9p2000.L"
	INFER_UNITS="$(smbios_cred systemd.extra-unit.ci-infer.service "[Unit]\nDescription=agentOS local inference real test (CI only)\nAfter=systemd-sysusers.service systemd-tmpfiles-setup.service\nBefore=agentos-boot-report.service serial-getty@ttyS0.service\n[Service]\nType=oneshot\nTimeoutStartSec=1800\nUser=agentos-infer\nPrivateNetwork=yes\nStandardOutput=journal+console\nStandardError=journal+console\nEnvironment=AGENTOS_LLAMA_SERVER=/usr/lib/agentos/infer/llama-server AGENTOS_LLAMA_EMBED_MODEL=/usr/lib/agentos/infer/Qwen3-Embedding-0.6B-Q8_0.gguf AGENTOS_LLAMA_EMBED_SHA256=$PIN\nExecStartPre=+/bin/sh -c 'mkdir -p /run/agentos-ci-infer && mount -t 9p -o $P9,ro infer /run/agentos-ci-infer'\nExecStart=/bin/sh -c '/run/agentos-ci-infer/infer.test -test.run ^TestRealRuntime -test.v -test.timeout 25m; echo agentos-infer-boot: DONE'\n")"
	INFER_UNITS="$INFER_UNITS$(smbios_cred systemd.unit-dropin.multi-user.target '[Unit]\nWants=ci-infer.service\n')"
	copy "$W/infer.raw"
	TMO=2400 EXTRA="-virtfs local,path=$IS,mount_tag=infer,security_model=none,readonly=on$INFER_UNITS" \
		UNTIL="agentos-infer-boot: DONE\|agentos-health: FAIL" boot "$W/console-infer.log" "$W/infer.raw"
	grep -a -- "--- \|infer\.test\|^ok \|^FAIL\|^PASS" "$W/console-infer.log" | guest_echo || true
	has "$W/console-infer.log" "agentos-infer-boot: DONE"
	has "$W/console-infer.log" "PASS: TestRealRuntimeEmbed"
	hasnt "$W/console-infer.log" "SKIP: TestRealRuntimeEmbed"
	hasnt "$W/console-infer.log" "FAIL: TestRealRuntime"
	rm -rf "$W/infer.raw" "$IS"
fi

# Prints "ci_boot: G1 PROVEN" (a prefix only the host script uses; the guest console is never given it,
# and the run fails if the console shows the verdict text) only when $2, the run's $fail, is exactly 0
# and the DONE line in $1 has pass>0 and fail, xfail, xpass and blocked all 0. A failed run prints
# "ci_boot: G1 NOT PROVEN (run failed)" whatever $1 holds; otherwise
# "ci_boot: G1 NOT PROVEN xfail=N blocked=M".
g1_verdict() {
	awk -v runfail="${2-}" '{ gsub(/\r/, ""); for (i = 1; i <= NF; i++) if (split($i, kv, "=") == 2) n[kv[1]] = kv[2] }
	END {
		if (runfail != "0")
			print "ci_boot: G1 NOT PROVEN (run failed)"
		else if (n["pass"] + 0 > 0 && n["fail"] == "0" && n["xfail"] == "0" && n["xpass"] == "0" && n["blocked"] == "0")
			print "ci_boot: G1 PROVEN"
		else
			printf "ci_boot: G1 NOT PROVEN xfail=%s blocked=%s\n", (n["xfail"] == "" ? "?" : n["xfail"]), (n["blocked"] == "" ? "?" : n["blocked"])
	}' "$1"
}

# Reads the guest console $1 and, only if every check below passes, writes the one DONE line to $2.
# Every line carrying the driver's prefix is echoed with ANSI, CR and other non-printable bytes cleaned out and "console| " in front,
# so a guest line can neither start with "ci_boot:" (the host's verdict prefix) nor with "::" (a
# workflow command). Exits non-zero, printing why, unless every such line starts with the prefix and
# is a PASS, FAIL, XFAIL(#N), XPASS, BLOCKED or NOTE line or the DONE line, there is exactly one DONE and
# it is the last, and its counts equal the step lines before it. The counts are the in-guest
# driver's own; this cross-check raises the cost of a forged console but a guest that forges the
# whole of it still passes (tools/ASSUMPTIONS.md D27).
e2e_console() {
	clean <"$1" | LC_ALL=C awk -v donefile="$2" '
	function miss(m) { print "ci_boot: MISS console: " m; bad = 1 }
	{
		l = $0
		gsub(/G1 (NOT )?PROVEN/, "G1 [verdict-text]", l)
	}
	index(l, "agentos-e2e: ") == 0 { next }
	{ print "console| " l }
	{
		# The console carries each line as journald prints it: an optional login prompt, the kernel
		# timestamp and the driver unit tag (box-e2e), then the driver text. Only that exact lead-in is accepted.
		a = l
		sub(/^(agentos login: )?(\[ *[0-9]+\.[0-9]+\] )?box-e2e\[[0-9]+\]: /, "", a)
	}
	index(a, "agentos-e2e: ") != 1 { miss("driver text not at the start of its line"); next }
	{
		r = substr(a, 14)
		if (ndone > 0) miss("line after DONE")
	}
	r ~ /^PASS [A-Za-z0-9_-]+$/ { c["pass"]++; next }
	r ~ /^FAIL [A-Za-z0-9_-]+ / { c["fail"]++; next }
	r ~ /^XFAIL\(#[0-9]+\) [A-Za-z0-9_-]+ / { c["xfail"]++; next }
	r ~ /^XPASS [A-Za-z0-9_-]+ expected to fail \(#[0-9]+\) but passed$/ { c["xpass"]++; next }
	r ~ /^BLOCKED [A-Za-z0-9_-]+ after [A-Za-z0-9_-]+$/ { c["blocked"]++; next }
	# A note names its step and carries lower-case words and counts only; it is no step (#2170).
	r ~ /^NOTE [A-Za-z0-9_-]+ [a-z0-9=-]+( [a-z0-9=-]+)*$/ { next }
	r ~ /^DONE pass=[0-9]+ fail=[0-9]+ xfail=[0-9]+ xpass=[0-9]+ blocked=[0-9]+$/ {
		ndone++
		done = "agentos-e2e: " r
		n = split(r, kv, /[ =]/)
		for (i = 2; i < n; i += 2) d[kv[i]] = kv[i + 1]
		next
	}
	{ miss("unrecognised driver line") }
	END {
		if (ndone != 1) miss("expected exactly one DONE line, found " ndone + 0)
		else {
			split("pass fail xfail xpass blocked", k, " ")
			for (i = 1; i <= 5; i++)
				if (d[k[i]] + 0 != c[k[i]] + 0) miss("DONE " k[i] "=" d[k[i]] " but " c[k[i]] + 0 " step lines")
		}
		# A console that failed any check leaves no DONE line behind for the verdict to read.
		if (!bad) print done > donefile
		exit bad
	}'
}

# The end-to-end run on a fresh copy with a cable in. Each step prints one line: PASS, FAIL,
# XFAIL(#issue) for a step on the expected-failure list, XPASS for one of those that passed (so the
# list is pruned), or BLOCKED after an earlier failure; then a DONE line with the counts.
if [ -n "${E2E:-}" ]; then
	cred() { printf ' -smbios type=11,value=io.systemd.credential.binary:%s=%s' "$1" "$(base64 -w0 "$HERE/e2e/$2")"; }
	copy "$W/e2e.raw" 24G
	# agentos-e2e-seal's 9p mount must reach the host for agentos-e2e: its drop-in lifts the main-side
	# mask (agentos-.service.d/50-main-side.conf).
	# A host disk beside the drive here too: setup's services and the agent machines run on this boot.
	H2=$W/host-e2e.raw
	host_disk "$H2"
	host2_before=$(sha256sum <"$H2")
	EXTRA="-virtfs local,path=$(realpath "$E2E"),mount_tag=e2e,security_model=none,readonly=on$(cred systemd.extra-unit.agentos-e2e-seal.service agentos-e2e-seal.service)$(smbios_cred 'systemd.unit-dropin.agentos-e2e-seal.service~99-ci-unmask' '[Service]\nInaccessiblePaths=\n')$(cred systemd.extra-unit.agentos-e2e.service agentos-e2e.service)$(cred systemd.unit-dropin.multi-user.target multi-user.conf)$(cred systemd.unit-dropin.agentos-modem.service agentos-modem.conf)$(cred systemd.unit-dropin.agentos-egress.service agentos-egress.conf)" \
		NIC="user,model=virtio-net-pci" UNTIL="agentos-e2e: DONE\|agentos-health: FAIL" boot "$W/console-e2e.log" "$W/e2e.raw" "$H2"
	[ "$(sha256sum <"$H2")" = "$host2_before" ] && echo "ok   host disk unchanged (e2e boot)" || { echo "MISS host disk unchanged (e2e boot)"; fail=1; }
	disks_none "$W/console-e2e.log" "agentos-disks:"
	disks_none "$W/console-e2e.log" "agentos-disks-end:"
	rm -f "$H2"
	# The guest writes this console, so none of it is trusted as it stands: e2e_console echoes each
	# driver line sanitised and prefixed, and accepts the log only with exactly one strictly
	# anchored DONE, last, whose counts match the step lines before it.
	: >"$W/e2e-done.log"
	e2e_console "$W/console-e2e.log" "$W/e2e-done.log" || fail=1
	has "$W/console-e2e.log" "agentos-e2e: DONE"
	has "$W/e2e-done.log" " fail=0 "
	has "$W/e2e-done.log" " xpass=0 "
	hasnt "$W/console-e2e.log" "agentos-e2e: FAIL"
	hasnt "$W/console-e2e.log" "agentos-e2e: XPASS"
	# The verdict is the host's alone: no console, from any of the five boots, may carry its text,
	# read both raw (text inside an OSC body, which cleaning deletes) and cleaned (text split by
	# escape sequences), so a guest that writes it fails the run whichever boot it did it in
	# (tools/ASSUMPTIONS.md D27).
	for c in console console-reboot console-two-drives console-slice console-e2e; do
		[ -f "$W/$c.log" ] || continue
		for v in "G1 PROVEN" "G1 NOT PROVEN"; do
			{ cat "$W/$c.log"; clean <"$W/$c.log"; } | grep -aqF "$v" && { echo "UNEXPECTED $v in $c.log"; fail=1; } || echo "ok   no \"$v\" in $c.log"
		done
	done
	# The G1 freeze lifts only on a run whose DONE line reads fail=0 xfail=0 blocked=0
	# (tools/ASSUMPTIONS.md D27). A green check with expected failures is not that run, so the
	# verdict gets its own host-only line in this job's log (not the console artifact); it does not
	# change whether the check passes. It is the run's last check: a run that failed anywhere (this
	# block or any earlier one, so $fail is not 0) prints NOT PROVEN, whatever the DONE line says.
	g1_verdict "$W/e2e-done.log" "$fail"
	rm -f "$W/e2e.raw" "$W/e2e-done.log"
fi
exit $fail
