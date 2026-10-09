#!/bin/sh
# A fake runsc for the exec tests (SR2-3h). It behaves as runsc
# release-20260928.0 does: util.Errorf writes its message to stderr and,
# as a JSON line, to the --log file; info lines go to --debug-log; the
# guest's pid is written to --internal-pid-file once the guest starts.
# The guest command's first word picks the case. Every runsc message
# names $FAKE_RUNSC_CANARY, a synthetic host path.
#
# latepanic is a Go runtime panic in runsc after the guest started
# (SR2-3m): its trace goes to stderr with no --log line, after the
# guest's own partial line, and runsc exits 2; the goroutine header is
# Go 1.23's at runsc's default traceback (system). fullpanic is a
# runtime fatal error, with the plain header, after the guest's stderr
# filled the cap. exit2 is a guest that exits 2 with a goroutine header
# but no panic line. deadpanic is latepanic at the deadline: runsc exits
# 2, but a process it left holds stdout and stderr open past the
# context's end, so Exec reads them after its context ended (Security S1
# on #391). killpanic writes its trace and is killed before it exits:
# Exec's context ends while runsc still runs (P1-4-flake). killquiet is
# a guest still running when the context ends, with nothing from runsc.
# Each of the three creates $FAKE_RUNSC_MARK at the point where its test
# ends the context (deadpanic once runsc has been reaped), and deadpanic's
# leftover process holds the pipes until the test removes it, so neither
# order depends on timing.
#
# As runsc does, the fake gives the guest the host fd that --pass-fd M:2
# names as its stderr, and fd 2 otherwise; runsc's own messages always go
# to fd 2 (SR2-3n). The guest's stderr writes below go to fd 4, that fd.
# splitmarker, splitgap and splitheader interleave guest stderr writes
# inside the panic marker, between the marker and the goroutine header,
# and inside the header. sigpanic is a Go fatal signal trace: "SIGSEGV:"
# and "PC=", no marker. fillerpanic is a guest that writes "panic: " and
# 16 KiB of filler before runsc's trace. guestpanic is a guest that writes
# a whole Go panic trace to its stderr and exits 2.
#
# The next three fail after the pid write with text on runsc's own
# stderr and no --log line, at an exit other than 2 and with Exec's
# context alive (P1-4-flake-crashed). oompanic writes a trace and is
# killed by something other than Exec (a cgroup OOM kill): it kills
# itself, so its exit is -1. exit1text writes one line and exits 1.
# waitdelaytext writes a trace and exits 0, but a process it left holds
# stdout and stderr past ExecWaitDelay, so Exec's wait ends in
# ErrWaitDelay; the fake creates $FAKE_RUNSC_MARK first, and the
# leftover holds the pipes until the test removes it. exit0text writes
# one line to runsc's stderr and exits 0 with nothing holding the pipes:
# a successful exec, which stays a result.
#
# The rest fail before the pid is written, as runsc's exec does
# (runsc/cmd/exec.go, runsc/sandbox/sandbox.go, pkg/urpc/urpc.go,
# pkg/sentry/fsimpl/user/path.go, pkg/sentry/loader/loader.go at that
# tag): pidfail after the start, at the pid write (SR2-3q); lostcall when
# the sandbox's answer to ExecuteAsync is lost, so the command may have
# started; noconn before the call; nope* (a bare name) and /nope* and
# /denied (paths) when the program is not found or cannot be loaded
# (SR2-3p). The executing-command messages quote the argv as %q does.
log= dlog= pid= cmd= gfd=2
while [ $# -gt 0 ]; do
	case "$1" in
	--log=*) log=${1#--log=} ;;
	--debug-log=*) dlog=${1#--debug-log=} ;;
	--internal-pid-file) shift; pid=$1 ;;
	--pass-fd) shift; case "$1" in *:2) gfd=${1%:2} ;; esac ;;
	*_) cmd=$2; shift; break ;; # the container ID; the guest's argv follows
	esac
	shift
done
c=$FAKE_RUNSC_CANARY
eval "exec 4>&$gfd"
[ -n "$dlog" ] && echo "I runsc exec, root $c" >>"$dlog"
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
fail() {
	[ -n "$log" ] && printf '{"msg":"%s","level":"error"}' "$(esc "$1")" >>"$log"
	echo "$1" >&2
	exit "$2"
}
# insandbox fails as the sandbox call does, with $1 as its cause.
insandbox() {
	fail "executing processes for container: executing command &{\"\" [$qargv] [\"PATH=/usr/bin:/bin\"] \"/\"} in sandbox: $1" 1
}
qargv=
for a in "$@"; do qargv="$qargv${qargv:+ }\"$(esc "$a")\""; done
case "$cmd" in
prestart) fail "loading container failed: $c: no such file" 128 ;;
panic) echo "panic: open $c" >&2; exit 2 ;;
latepanic)
	echo 7 >"$pid"
	echo "guest out"
	printf 'guest err' >&4
	printf 'panic: open %s: permission denied\n\ngoroutine 1 gp=0xc000002380 m=0 mp=0x1f2e3c0 [running]:\nmain.main()\n\t%s/runsc/main.go:42 +0x1d\n' "$c" "$c" >&2
	exit 2
	;;
deadpanic)
	echo 7 >"$pid"
	echo "guest out"
	printf 'panic: open %s: permission denied\n\ngoroutine 1 [running]:\nmain.main()\n' "$c" >&2
	parent=$$
	(
		while kill -0 "$parent" 2>/dev/null; do sleep 0.01; done
		: >"$FAKE_RUNSC_MARK"
		i=0
		while [ -e "$FAKE_RUNSC_MARK" ] && [ $i -lt 1000 ]; do sleep 0.01; i=$((i + 1)); done
	) &
	exit 2
	;;
killpanic)
	echo 7 >"$pid"
	echo "guest out"
	printf 'panic: open %s: permission denied\n\ngoroutine 1 [running]:\nmain.main()\n' "$c" >&2
	: >"$FAKE_RUNSC_MARK"
	exec sleep 30
	;;
killquiet)
	echo 7 >"$pid"
	echo "guest out"
	: >"$FAKE_RUNSC_MARK"
	exec sleep 30
	;;
fullpanic)
	echo 7 >"$pid"
	head -c 4096 /dev/zero | tr '\0' g >&4
	printf 'fatal error: %s\n\ngoroutine 9 [running]:\nmain.main()\n' "$c" >&2
	exit 2
	;;
splitmarker)
	echo 7 >"$pid"
	printf 'pan' >&2; printf 'GUEST' >&4; printf 'ic: open %s: permission denied\n\n' "$c" >&2
	printf 'goroutine 1 [running]:\nmain.main()\n\t%s/runsc/main.go:42 +0x1d\n' "$c" >&2
	exit 2
	;;
splitgap)
	echo 7 >"$pid"
	printf 'panic: open %s: permission denied\n\n' "$c" >&2; printf 'GUEST\n' >&4
	printf 'goroutine 1 [running]:\nmain.main()\n\t%s/runsc/main.go:42 +0x1d\n' "$c" >&2
	exit 2
	;;
splitheader)
	echo 7 >"$pid"
	printf 'panic: open %s: permission denied\n\ngorou' "$c" >&2; printf 'GUEST' >&4
	printf 'tine 1 [running]:\nmain.main()\n\t%s/runsc/main.go:42 +0x1d\n' "$c" >&2
	exit 2
	;;
sigpanic)
	echo 7 >"$pid"
	echo "guest out"; echo "guest err" >&4
	printf 'SIGSEGV: segmentation violation\nPC=0x46e2a1 m=0 sigcode=1 addr=0x0\n\ngoroutine 1 gp=0xc000002380 m=0 mp=0x1f2e3c0 [running]:\nmain.main()\n\t%s/runsc/main.go:42 +0x1d\n' "$c" >&2
	exit 2
	;;
fillerpanic)
	echo 7 >"$pid"
	printf 'panic: ' >&4; head -c 16384 /dev/zero | tr '\0' f >&4
	printf 'panic: open %s: permission denied\n\ngoroutine 1 [running]:\nmain.main()\n' "$c" >&2
	exit 2
	;;
guestpanic)
	echo 7 >"$pid"; echo "guest out"
	printf 'panic: boom\n\ngoroutine 1 [running]:\nmain.main()\n' >&4
	exit 2
	;;
oompanic)
	echo 7 >"$pid"
	echo "guest out"
	printf 'panic: open %s: permission denied\n\ngoroutine 1 [running]:\nmain.main()\n' "$c" >&2
	kill -KILL $$
	;;
exit1text) echo 7 >"$pid"; echo "guest out"; echo "W runsc: $c" >&2; exit 1 ;;
exit0text) echo 7 >"$pid"; echo "guest out"; echo "W runsc: $c" >&2; exit 0 ;;
waitdelaytext)
	echo 7 >"$pid"
	echo "guest out"
	printf 'panic: open %s: permission denied\n\ngoroutine 1 [running]:\nmain.main()\n' "$c" >&2
	: >"$FAKE_RUNSC_MARK"
	(
		i=0
		while [ -e "$FAKE_RUNSC_MARK" ] && [ $i -lt 3000 ]; do sleep 0.01; i=$((i + 1)); done
	) 3>&- 4>&- &
	exit 0
	;;
exit2) echo 7 >"$pid"; echo "guest out"; echo "goroutine 1 [running]:" >&4; exit 2 ;;
pidfail) fail "writing internal pid file: open $c: no space left on device" 1 ;;
lostcall) insandbox 'urpc method "containerManager.ExecuteAsync" failed: EOF' ;;
noconn) insandbox "connecting to control server at PID 9: dial unix $c: connect: no such file or directory" ;;
nope*) insandbox "error finding executable \"$(esc "$cmd")\" in PATH [/usr/bin /bin]: no such file or directory" ;;
/nope*) insandbox "failed to load $cmd: no such file or directory" ;;
/denied) insandbox "failed to load $cmd: permission denied" ;;
wait) echo 7 >"$pid"; echo "guest out"; echo "guest err" >&4; fail "waiting on pid 7: $c" 1 ;;
*) echo 7 >"$pid"; echo "guest out"; echo "guest err" >&4; exit 3 ;;
esac
