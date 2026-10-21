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
# With E2E set to a directory holding a static box-e2e (broker/e2e/boxe2e), a fourth boot on a
# fresh copy runs the end-to-end setup run inside the box (#1688): e2e/ holds its unit and drop-ins,
# passed as SMBIOS credentials, which systemd honours only in a VM, so the image itself is unchanged.
# Usage: ci_boot.sh IMAGE [WORKDIR]. Console logs: WORKDIR/console.log, console-reboot.log,
# console-two-drives.log, console-e2e.log.
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
# ext4 filesystem, each holding a synthetic canary, built without loop devices or mounts. It sits
# beside the drive on the first boot, the one that grows root and writes the drive's GUIDs, and the
# box may read its partition table and nothing else, so it must come out byte-identical.
host_disk() {
	h=$1 t=$(mktemp -d "$W/host.XXXXXX")
	rm -f "$h"; truncate -s 256M "$h"
	printf '%s\n' 'label: gpt' 'size=64M, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B' \
		'size=64M, type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7' 'size=32M, type=0657FD6D-A4AB-43C4-84E5-0933C84B4F4F' \
		'type=0FC63DAF-8483-4772-8E79-3D69D8477DE4' | sfdisk -q "$h"
	echo agentos-ci-canary-host-disk >"$t/canary"
	for fs in esp data; do
		mkfs.vfat -C "$t/$fs" 65536 >/dev/null; mcopy -i "$t/$fs" "$t/canary" ::/canary
	done
	truncate -s 32M "$t/swap"; truncate -s 64M "$t/ext4"; mkswap -q "$t/swap"
	mkdir "$t/root"; cp "$t/canary" "$t/root/"; mkfs.ext4 -q -F -d "$t/root" "$t/ext4"
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
before=$(stat -c %s "$IMG")
# NetworkManager runs and manages nothing, and polkit answers for the join helper only (#936, I17,
# I21). The first boot runs this check as a unit passed as an SMBIOS credential, ordered before the
# boot report so its lines are on the console by then; the image itself is unchanged. The script
# rides inside the unit as base64, which holds no character systemd or the shell would expand.
nm_check() {
	cat <<'EOS'
say() { echo "agentos-nm: $*"; }
n=0
until nmcli -t -f DEVICE,STATE device 2>/dev/null | grep -q . || [ $n -ge 30 ]; do n=$((n + 1)); sleep 1; done
systemctl is-active --quiet NetworkManager.service && say "NetworkManager.service active" || say "FAIL NetworkManager.service not active"
dev=$(nmcli -t -f DEVICE,STATE device 2>/dev/null)
if [ -n "$dev" ] && [ -z "$(echo "$dev" | grep -v ':unmanaged$')" ]; then say "every device unmanaged"; else say "FAIL a device is managed: $dev"; fi
if [ -z "$(systemctl --failed --no-legend)" ]; then say "no failed units"; else say "FAIL failed units: $(systemctl --failed --no-legend | cut -d' ' -f1-2)"; fi
if [ -z "$(ls -A /etc/NetworkManager/system-connections 2>/dev/null)" ]; then say "no connection file on the drive"; else say "FAIL a connection file is on the drive"; fi
act=org.freedesktop.NetworkManager.settings.modify.system
runuser -u agentos-netjoin -- sh -c "exec pkcheck --action-id $act --process \$\$" && say "pkcheck yes for agentos-netjoin" || say "FAIL pkcheck no for agentos-netjoin"
runuser -u nobody -- sh -c "exec pkcheck --action-id $act --process \$\$" && say "FAIL pkcheck yes for nobody" || say "pkcheck no for nobody"
say done
EOS
}
nm_cred() { printf ' -smbios type=11,value=io.systemd.credential.binary:%s=%s' "$1" "$(printf '%b' "$2" | base64 -w0)"; }
NM_UNIT="[Unit]\nDescription=agentOS NetworkManager check (CI only)\nAfter=NetworkManager.service\nBefore=agentos-boot-report.service serial-getty@ttyS0.service\n[Service]\nType=oneshot\nTimeoutStartSec=120\nStandardOutput=journal+console\nStandardError=journal+console\nExecStart=/bin/sh -c 'echo $(nm_check | base64 -w0) | base64 -d | sh'\n"
NM_EXTRA="$(nm_cred systemd.extra-unit.agentos-nm-check.service "$NM_UNIT")$(nm_cred systemd.unit-dropin.multi-user.target '[Unit]\nWants=agentos-nm-check.service\n')"

# Forwards from the host to box ports 22, 80, 443, 18789 and 5355 (resolved's LLMNR): each must be
# dropped (I11, I19). The LAN NIC carries the same probe over IPv6 (#1457).
EXTRA="$NM_EXTRA" NIC="user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:18022-:22,hostfwd=tcp:127.0.0.1:18080-:80,hostfwd=tcp:127.0.0.1:18443-:443,hostfwd=tcp:127.0.0.1:18789-:18789,hostfwd=tcp:127.0.0.1:15355-:5355" \
	LAN="socket,model=virtio-net-pci,listen=127.0.0.1:18600" PROBE6="127.0.0.1:18600 22 80 443 18789 5355" \
	PROBE="18022:22 18080:80 18443:443 18789:18789 15355:5355" boot "$W/console.log" "$D" "$H"
for want in "agentos-health: PASS secure_boot=on usr=verity inbound=drop swap=off dumps=off forward=off" "agentos-boot: bless=good" "agentos-drive-id: assigned"; do
	has "$W/console.log" "$want"
done
# NetworkManager is up and manages no device; polkit lets the join helper write system connections
# and no other user; nothing is on the drive. The health line above still reads forward=off
# inbound=drop, and the probes below find every port dropped (DEV-2).
for want in "agentos-nm: NetworkManager.service active" "agentos-nm: every device unmanaged" "agentos-nm: no failed units" \
	"agentos-nm: no connection file on the drive" "agentos-nm: pkcheck yes for agentos-netjoin" "agentos-nm: pkcheck no for nobody" "agentos-nm: done"; do
	has "$W/console.log" "$want"
done
hasnt "$W/console.log" "agentos-nm: FAIL"
# polkitd is 0.106 or later (JS rules), read from the package manifest mkosi wrote beside the image.
if python3 "$HERE/compare_manifests.py" --polkitd "$(dirname "$IMG")"; then
	echo "ok   polkitd 0.106 or later"
else
	echo "MISS polkitd 0.106 or later in the manifest beside $IMG"; fail=1
fi
# The host disk is not the boot drive (drive-id saw one boot partition), nothing wrote to it, and
# the guest reports no mount or swap on it (a read-only mount leaves the bytes unchanged, IMG-1-1).
[ "$(sha256sum <"$H")" = "$host_before" ] && echo "ok   host disk unchanged" || { echo "MISS host disk unchanged"; fail=1; }
has "$W/console.log" "agentos-disks: foreign=none"
rm -f "$H"
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
cat "$W/console.log.probe" 2>/dev/null || true
for port in 22 80 443 18789; do
	has "$W/console.log.probe" "agentos-probe: $port dropped"
done
has "$W/console.log.probe" "agentos-probe: 5355 dropped"
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
TMO=600 boot "$W/console-reboot.log" "$D"
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

# The station beside the access point (#936 r4b, image/ASSUMPTIONS.md P2-2w-c3-r4b-2-I1): a fresh copy boots
# with mac80211_hwsim's two radios. wlan0 stands in for the box's; wlan1's radio is moved into its
# own network namespace before the loader starts (the loader takes every radio it sees, I16), and a
# test WPA2 access point with a synthetic name and password runs there. The image ships no iw, so
# the host's goes in on a read-only 9p share beside the guest's two scripts; the units ride as
# SMBIOS credentials like e2e/'s, so the image itself is unchanged. The join is CI's own, through
# nmcli as root with an in-memory connection: the product's helper still answers failed until the
# sealed store (#935). Its lines go to the console as "agentos-hwsim: ..."; a NOTE line reports and
# checks nothing.
HWSIM_PSK=agentos-ci-canary-hwsim-psk
hwsim_setup() {
	cat <<'EOS'
say() { echo "agentos-hwsim: $*"; }
modprobe mac80211_hwsim radios=2 || say "FAIL modprobe mac80211_hwsim"
n=0
until [ -e /sys/class/net/wlan0/phy80211 ] && [ -e /sys/class/net/wlan1/phy80211 ] || [ $n -ge 30 ]; do n=$((n + 1)); sleep 1; done
phy=$(cat /sys/class/net/wlan1/phy80211/name 2>/dev/null)
# The seller seals the sticker's setup network before the box ships (agentos-seller, HW-10); CI's
# image has none, and without it the loader serves nothing. A synthetic one, root's 0600, once.
# The name must carry claim.SetupSSIDPrefix, the old product name: it is written as a JSON escape so
# this file adds no product text (tests/test_product_name.py).
f=/var/lib/agentos/setup-net.json
[ -e $f ] || (umask 077 && printf '%s' '{"ssid":"\u0041gentOS-Setup-CTST","password":"CANA-RYHW-SMC2-TEST"}' >$f)
if [ -s $f ]; then say "setup network sealed"; else say "FAIL sealing the setup network"; fi
ip netns add hwsimap
if [ -n "$phy" ] && /run/agentos-hwsim/share/iw phy "$phy" set netns name hwsimap && [ ! -e /sys/class/net/wlan1 ]; then
	say "test radio in its own namespace"
else
	say "FAIL moving the test radio into its own namespace"
fi
EOS
}
hwsim_check() {
	cat <<'EOS'
say() { echo "agentos-hwsim: $*"; }
S=/run/agentos-hwsim/share R=/run/agentos-hwsim
IW=$S/iw SSID=agentos-ci-hwsim PSK=$(cat $S/psk) NAME=box.hwsim.agentos-ci.test
ns() { ip netns exec hwsimap "$@"; }
# until N CMD...: run CMD each second until it succeeds or N seconds pass.
until_ok() { t=$1; shift; i=0; until "$@" || [ $i -ge "$t" ]; do i=$((i + 1)); sleep 1; done; "$@"; }
box_channel() { $IW dev wlan0 info 2>/dev/null | sed -n 's/.*channel \([0-9]*\) .*/\1/p'; }
ap_up() { $IW dev wlan0 info 2>/dev/null | grep -q "type AP" && [ -n "$(box_channel)" ]; }
sta() { [ -e /sys/class/net/wlsta0 ]; }
joined() { nmcli -g GENERAL.STATE device show wlsta0 2>/dev/null | grep -q '^100'; }
unjoined() { ! joined; }
# The interfaces on wlan0's radio: wlan0 and wlsta0, never a second station.
radio_ifs() { cat /sys/class/net/*/phy80211/name 2>/dev/null | grep -cx "$(cat /sys/class/net/wlan0/phy80211/name)"; }
managed() { nmcli -t -f DEVICE,STATE device 2>/dev/null | grep -v ':unmanaged$' | cut -d: -f1 | tr '\n' ' '; }
only_sta() { [ "$(managed)" = "wlsta0 " ]; }
not_exempt() { ! nft list set inet agentos_inbound exempt 2>/dev/null | grep -q wlsta0; }
logged() { journalctl -b -u agentos-ap -o cat 2>/dev/null | grep -c "$1"; }
served_again() { [ "$(logged "serving the")" -gt "$served" ]; }
same_station() { [ "$(cat /sys/class/net/wlsta0/ifindex 2>/dev/null)" = "$idx" ]; }
check() { if "$@"; then say "$MSG"; else say "FAIL $MSG"; fi; }
# test_ap CHANNEL: the test access point, with DHCP and DNS, (re)started on CHANNEL.
test_ap() {
	for p in hostapd dnsmasq; do [ -f $R/$p.pid ] && kill "$(cat $R/$p.pid)" 2>/dev/null; rm -f $R/$p.pid; done
	sleep 1
	printf '%s\n' interface=wlan1 driver=nl80211 "ssid=$SSID" hw_mode=g "channel=$1" wpa=2 \
		wpa_key_mgmt=WPA-PSK rsn_pairwise=CCMP "wpa_passphrase=$PSK" >$R/ap.conf
	chmod 0600 $R/ap.conf
	ns hostapd -B -P $R/hostapd.pid $R/ap.conf >/dev/null 2>&1
	ns dnsmasq --interface=wlan1 --bind-interfaces --listen-address=192.168.77.1 --no-resolv --no-hosts \
		--dhcp-range=192.168.77.10,192.168.77.50,255.255.255.0,1h --address=/$NAME/192.168.77.1 \
		--dhcp-leasefile=$R/leases --pid-file=$R/dnsmasq.pid --user=root --group=root >/dev/null 2>&1
	until_ok 20 ns sh -c '[ "$(cat /sys/class/net/wlan1/operstate)" = up ]'
}
# join NAME IPV4: an in-memory connection to the test access point on wlsta0, activated.
join() {
	nmcli connection add save no type wifi ifname wlsta0 con-name "$1" ssid "$SSID" wifi-sec.key-mgmt wpa-psk \
		wifi-sec.psk "$PSK" ipv4.method "$2" ipv6.method disabled connection.autoconnect "$3" >/dev/null 2>&1
	nmcli --wait 60 connection up "$1" >/dev/null 2>&1
}
nopsk() {
	MSG="the PSK is in no journal line"; check [ "$(journalctl -b -o cat 2>/dev/null | grep -cF "$PSK")" = 0 ]
	MSG="the PSK is in no file on the drive"
	check [ -z "$(grep -rlsF "$PSK" /etc /var /root /home /srv /opt /usr/local 2>/dev/null)" ]
}

MSG="wlsta0 exists"; check until_ok 180 sta
MSG="the box's access point serves"; check until_ok 120 ap_up
# Why not, when it does not: the loader logs no network name or password (I16), nor does iw's info.
if ! ap_up; then
	journalctl -b -u agentos-ap -o cat 2>/dev/null | grep -v "agentos-ap: station: " | tail -30 | while read -r l; do say "NOTE loader| $l"; done
	say "NOTE loader station errors=$(logged "agentos-ap: station: ")"
	journalctl -b -u agentos-ap -o cat 2>/dev/null | grep "agentos-ap: station: " | sort | uniq -c | while read -r l; do say "NOTE loader| $l"; done
	$IW dev 2>/dev/null | while read -r l; do say "NOTE iw| $l"; done
	say "NOTE agentos-ap $(systemctl is-active agentos-ap.service) restarts=$(systemctl show -p NRestarts --value agentos-ap.service)"
fi
MSG="wlsta0 on the box's radio"; check [ "$(cat /sys/class/net/wlsta0/phy80211/name 2>/dev/null)" = "$(cat /sys/class/net/wlan0/phy80211/name)" ]
MSG="one station on the radio"; check [ "$(radio_ifs)" = 2 ]
MSG="NetworkManager manages only wlsta0"; check until_ok 30 only_sta
only_sta || say "NOTE managed devices: $(managed)"
MSG="wlsta0 not exempt from the inbound drop"; check not_exempt
MSG="the loader logged the station allowed"; check [ "$(logged "station wlsta0 beside wlan0 on allowed")" -gt 0 ]

if [ "$(cat $S/mode)" = reboot ]; then
	MSG="no saved network after the reboot"; check [ -z "$(nmcli -t -f NAME connection show 2>/dev/null)" ]
	MSG="wlsta0 not joined after the reboot"; check unjoined
	nopsk
	say done
	exit 0
fi

ns ip link set lo up
ns ip addr add 192.168.77.1/24 dev wlan1
# #2629: on a radio with one channel, a station join on another channel than the access point's.
# What happens is reported, not checked: the brief's follow assumes the join succeeds first.
box=$(box_channel); off=1; [ "$box" = 1 ] && off=11
test_ap $off
if join ci-off disabled no; then r=joined; else r=refused; fi
sleep 8
say "NOTE single-channel join on channel $off beside the access point on $box: $r; access point moves=$(logged "moving the access point"), now on $(box_channel)"
journalctl -b -k -o cat 2>/dev/null | grep -a "wlsta0" | tail -6 | while read -r l; do say "NOTE kernel| $l"; done
nmcli connection delete ci-off >/dev/null 2>&1
until_ok 20 unjoined

# The join the brief's matrix needs, on the access point's own channel.
test_ap "$(box_channel)"
MSG="station joined"; check join ci-same auto yes
addr=$(ip -4 -o addr show dev wlsta0 | awk '{ print $4 }' | cut -d/ -f1 | head -1)
MSG="station has a lease"; check [ -n "$addr" ]
MSG="DNS resolves over the station"
check sh -c "resolvectl query $NAME 2>/dev/null | grep -q '192.168.77.1.*link: wlsta0'"
MSG="the box's access point stays up"; check ap_up
MSG="station reaches the test network"; check timeout 5 bash -c 'exec 3<>/dev/tcp/192.168.77.1/53'
for port in 22 80 443 18789 5355; do
	ns timeout 4 bash -c "exec 3<>/dev/tcp/$addr/$port" 2>/dev/null
	rc=$?
	if [ $rc = 124 ]; then say "probe $port dropped"; else say "FAIL probe $port answered (rc=$rc)"; fi
done

# Loader restart: wlsta0 survives, is not duplicated, and stays joined; the access point comes back.
idx=$(cat /sys/class/net/wlsta0/ifindex)
served=$(logged "serving the")
systemctl restart agentos-ap.service
until_ok 120 served_again
MSG="after the loader restart, the box's access point serves again"; check until_ok 60 ap_up
MSG="wlsta0 survived the loader restart"; check same_station
MSG="after the loader restart, one station on the radio"; check [ "$(radio_ifs)" = 2 ]
MSG="the station stayed joined after the loader restart"; check until_ok 60 joined

# Helper restart: no change to wlsta0 or the connection.
systemctl restart agentos-netjoin.service
sleep 3
MSG="the helper restart left the station"; check eval 'same_station && joined'
nopsk
say done
EOS
}
hwsim_cred() { printf ' -smbios type=11,value=io.systemd.credential.binary:%s=%s' "$1" "$(printf '%b' "$2" | base64 -w0)"; }
HWSIM_UNITS="$(hwsim_cred systemd.extra-unit.agentos-hwsim-setup.service "[Unit]\nDescription=agentOS hwsim radios (CI only)\nAfter=systemd-udevd.service systemd-tmpfiles-setup.service\nBefore=agentos-ap.service NetworkManager.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nStandardOutput=journal+console\nStandardError=journal+console\nExecStart=/bin/mkdir -p /run/agentos-hwsim/share\nExecStart=/bin/mount -t 9p -o trans=virtio,version=9p2000.L,ro hwsim /run/agentos-hwsim/share\nExecStart=/bin/sh /run/agentos-hwsim/share/setup.sh\n")"
HWSIM_UNITS="$HWSIM_UNITS$(hwsim_cred systemd.extra-unit.agentos-hwsim-check.service "[Unit]\nDescription=agentOS station check (CI only)\nRequires=agentos-hwsim-setup.service\nAfter=agentos-hwsim-setup.service agentos-ap.service NetworkManager.service agentos-netjoin.service\nBefore=agentos-boot-report.service serial-getty@ttyS0.service\n[Service]\nType=oneshot\nTimeoutStartSec=900\nStandardOutput=journal+console\nStandardError=journal+console\nExecStart=/bin/bash /run/agentos-hwsim/share/check.sh\n")"
HWSIM_UNITS="$HWSIM_UNITS$(hwsim_cred systemd.unit-dropin.multi-user.target '[Unit]\nWants=agentos-hwsim-setup.service agentos-hwsim-check.service\n')"
# The host's iw, or Ubuntu's package unpacked without installing it (apt verifies it).
hwsim_iw() {
	command -v iw && return
	t=$(mktemp -d "$W/iw.XXXXXX")
	(cd "$t" && apt-get download -q iw >/dev/null 2>&1) && dpkg-deb -x "$t"/iw_*.deb "$t/x" && ls "$t/x/usr/sbin/iw" "$t/x/sbin/iw" 2>/dev/null | head -1
}
HS=$W/hwsim-share
rm -rf "$HS"; mkdir -p "$HS"
iw=$(hwsim_iw || true)
if [ -n "$iw" ] && cp "$iw" "$HS/iw"; then echo "ok   iw for the hwsim boot: $iw"; else echo "MISS iw for the hwsim boot"; fail=1; fi
hwsim_setup >"$HS/setup.sh"; hwsim_check >"$HS/check.sh"; printf '%s' "$HWSIM_PSK" >"$HS/psk"; echo first >"$HS/mode"
HWSIM_EXTRA="-virtfs local,path=$HS,mount_tag=hwsim,security_model=none,readonly=on$HWSIM_UNITS"
copy "$W/hwsim.raw"
EXTRA="$HWSIM_EXTRA" boot "$W/console-hwsim.log" "$W/hwsim.raw"
grep -a "agentos-hwsim: NOTE" "$W/console-hwsim.log" | guest_echo || true
for want in "setup network sealed" "test radio in its own namespace" "wlsta0 exists" "the box's access point serves" "wlsta0 on the box's radio" \
	"one station on the radio" "NetworkManager manages only wlsta0" "wlsta0 not exempt from the inbound drop" \
	"the loader logged the station allowed" "station joined" "station has a lease" "DNS resolves over the station" \
	"the box's access point stays up" "station reaches the test network" "probe 22 dropped" "probe 80 dropped" \
	"probe 443 dropped" "probe 18789 dropped" "probe 5355 dropped" "after the loader restart, the box's access point serves again" \
	"wlsta0 survived the loader restart" "after the loader restart, one station on the radio" \
	"the station stayed joined after the loader restart" "the helper restart left the station" \
	"the PSK is in no journal line" "the PSK is in no file on the drive" "done"; do
	has "$W/console-hwsim.log" "agentos-hwsim: $want"
done
hasnt "$W/console-hwsim.log" "agentos-hwsim: FAIL"
hasnt "$W/console-hwsim.log" "$HWSIM_PSK"
has "$W/console-hwsim.log" "agentos-health: PASS secure_boot=on usr=verity inbound=drop swap=off dumps=off forward=off"
# The reboot: wlsta0 comes back, and with no sealed store there is no saved network.
echo reboot >"$HS/mode"
TMO=600 EXTRA="$HWSIM_EXTRA" boot "$W/console-hwsim-reboot.log" "$W/hwsim.raw"
for want in "setup network sealed" "test radio in its own namespace" "wlsta0 exists" "the box's access point serves" "wlsta0 on the box's radio" \
	"one station on the radio" "NetworkManager manages only wlsta0" "wlsta0 not exempt from the inbound drop" \
	"no saved network after the reboot" "wlsta0 not joined after the reboot" "the PSK is in no file on the drive" "done"; do
	has "$W/console-hwsim-reboot.log" "agentos-hwsim: $want"
done
hasnt "$W/console-hwsim-reboot.log" "agentos-hwsim: FAIL"
has "$W/console-hwsim-reboot.log" "agentos-health: PASS secure_boot=on usr=verity"
rm -rf "$W/hwsim.raw" "$HS"

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
	# A host disk beside the drive here too: setup's services and the agent machines run on this boot.
	H2=$W/host-e2e.raw
	host_disk "$H2"
	host2_before=$(sha256sum <"$H2")
	EXTRA="-virtfs local,path=$(realpath "$E2E"),mount_tag=e2e,security_model=none,readonly=on$(cred systemd.extra-unit.agentos-e2e-seal.service agentos-e2e-seal.service)$(cred systemd.extra-unit.agentos-e2e.service agentos-e2e.service)$(cred systemd.unit-dropin.multi-user.target multi-user.conf)$(cred systemd.unit-dropin.agentos-modem.service agentos-modem.conf)$(cred systemd.unit-dropin.agentos-egress.service agentos-egress.conf)" \
		NIC="user,model=virtio-net-pci" UNTIL="agentos-e2e: DONE\|agentos-health: FAIL" boot "$W/console-e2e.log" "$W/e2e.raw" "$H2"
	[ "$(sha256sum <"$H2")" = "$host2_before" ] && echo "ok   host disk unchanged (e2e boot)" || { echo "MISS host disk unchanged (e2e boot)"; fail=1; }
	has "$W/console-e2e.log" "agentos-disks: foreign=none"
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
	# The verdict is the host's alone: no console, from any of the four boots, may carry its text,
	# read both raw (text inside an OSC body, which cleaning deletes) and cleaned (text split by
	# escape sequences), so a guest that writes it fails the run whichever boot it did it in
	# (tools/ASSUMPTIONS.md D27).
	for c in console console-reboot console-two-drives console-e2e; do
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
