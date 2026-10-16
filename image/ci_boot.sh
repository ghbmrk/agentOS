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

D=$W/disk.raw
copy "$D"
before=$(stat -c %s "$IMG")
# Forwards from the host to box ports 22, 80, 443, 18789 and 5355 (resolved's LLMNR): each must be
# dropped (I11, I19). The LAN NIC carries the same probe over IPv6 (#1457).
NIC="user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:18022-:22,hostfwd=tcp:127.0.0.1:18080-:80,hostfwd=tcp:127.0.0.1:18443-:443,hostfwd=tcp:127.0.0.1:18789-:18789,hostfwd=tcp:127.0.0.1:15355-:5355" \
	LAN="socket,model=virtio-net-pci,listen=127.0.0.1:18600" PROBE6="127.0.0.1:18600 22 80 443 18789 5355" \
	PROBE="18022:22 18080:80 18443:443 18789:18789 15355:5355" boot "$W/console.log" "$D"
for want in "agentos-health: PASS secure_boot=on usr=verity inbound=drop swap=off dumps=off forward=off" "agentos-boot: bless=good" "agentos-drive-id: assigned"; do
	has "$W/console.log" "$want"
done
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
# is a PASS, FAIL, XFAIL(#N), XPASS or BLOCKED line or the DONE line, there is exactly one DONE and
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
	EXTRA="-virtfs local,path=$(realpath "$E2E"),mount_tag=e2e,security_model=none,readonly=on$(cred systemd.extra-unit.agentos-e2e-seal.service agentos-e2e-seal.service)$(cred systemd.extra-unit.agentos-e2e.service agentos-e2e.service)$(cred systemd.unit-dropin.multi-user.target multi-user.conf)$(cred systemd.unit-dropin.agentos-modem.service agentos-modem.conf)$(cred systemd.unit-dropin.agentos-egress.service agentos-egress.conf)" \
		NIC="user,model=virtio-net-pci" UNTIL="agentos-e2e: DONE\|agentos-health: FAIL" boot "$W/console-e2e.log" "$W/e2e.raw"
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
