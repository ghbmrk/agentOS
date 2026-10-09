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
# 2 at once, but a process it left holds stderr open past the context's
# end, so Exec returns after its deadline (Security S1 on #391).
#
# The rest fail before the pid is written, as runsc's exec does
# (runsc/cmd/exec.go, runsc/sandbox/sandbox.go, pkg/urpc/urpc.go,
# pkg/sentry/fsimpl/user/path.go, pkg/sentry/loader/loader.go at that
# tag): pidfail after the start, at the pid write (SR2-3q); lostcall when
# the sandbox's answer to ExecuteAsync is lost, so the command may have
# started; noconn before the call; nope* (a bare name) and /nope* and
# /denied (paths) when the program is not found or cannot be loaded
# (SR2-3p). The executing-command messages quote the argv as %q does.
log= dlog= pid= cmd=
while [ $# -gt 0 ]; do
	case "$1" in
	--log=*) log=${1#--log=} ;;
	--debug-log=*) dlog=${1#--debug-log=} ;;
	--internal-pid-file) shift; pid=$1 ;;
	*_) cmd=$2; shift; break ;; # the container ID; the guest's argv follows
	esac
	shift
done
c=$FAKE_RUNSC_CANARY
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
	printf 'guest err' >&2
	printf 'panic: open %s: permission denied\n\ngoroutine 1 gp=0xc000002380 m=0 mp=0x1f2e3c0 [running]:\nmain.main()\n\t%s/runsc/main.go:42 +0x1d\n' "$c" "$c" >&2
	exit 2
	;;
deadpanic)
	echo 7 >"$pid"
	echo "guest out"
	printf 'panic: open %s: permission denied\n\ngoroutine 1 [running]:\nmain.main()\n' "$c" >&2
	sleep 0.5 >&2 &
	exit 2
	;;
fullpanic)
	echo 7 >"$pid"
	head -c 4096 /dev/zero | tr '\0' g >&2
	printf 'fatal error: %s\n\ngoroutine 9 [running]:\nmain.main()\n' "$c" >&2
	exit 2
	;;
exit2) echo 7 >"$pid"; echo "guest out"; echo "goroutine 1 [running]:" >&2; exit 2 ;;
pidfail) fail "writing internal pid file: open $c: no space left on device" 1 ;;
lostcall) insandbox 'urpc method "containerManager.ExecuteAsync" failed: EOF' ;;
noconn) insandbox "connecting to control server at PID 9: dial unix $c: connect: no such file or directory" ;;
nope*) insandbox "error finding executable \"$(esc "$cmd")\" in PATH [/usr/bin /bin]: no such file or directory" ;;
/nope*) insandbox "failed to load $cmd: no such file or directory" ;;
/denied) insandbox "failed to load $cmd: permission denied" ;;
wait) echo 7 >"$pid"; echo "guest out"; echo "guest err" >&2; fail "waiting on pid 7: $c" 1 ;;
*) echo 7 >"$pid"; echo "guest out"; echo "guest err" >&2; exit 3 ;;
esac
