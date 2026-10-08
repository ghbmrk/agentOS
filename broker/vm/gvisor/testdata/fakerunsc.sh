#!/bin/sh
# A fake runsc for the exec tests (SR2-3h). It behaves as runsc
# release-20260928.0 does: util.Errorf writes its message to stderr and,
# as a JSON line, to the --log file; info lines go to --debug-log; the
# guest's pid is written to --internal-pid-file once the guest starts.
# The guest command's first word picks the case. Every runsc message
# names $FAKE_RUNSC_CANARY, a synthetic host path.
log= dlog= pid= cmd=
while [ $# -gt 0 ]; do
	case "$1" in
	--log=*) log=${1#--log=} ;;
	--debug-log=*) dlog=${1#--debug-log=} ;;
	--internal-pid-file) shift; pid=$1 ;;
	*_) cmd=$2; break ;; # the container ID; the guest's argv follows
	esac
	shift
done
c=$FAKE_RUNSC_CANARY
[ -n "$dlog" ] && echo "I runsc exec, root $c" >>"$dlog"
fail() {
	[ -n "$log" ] && printf '{"msg":"%s","level":"error"}' "$1" >>"$log"
	echo "$1" >&2
	exit "$2"
}
case "$cmd" in
prestart) fail "loading container failed: $c: no such file" 128 ;;
panic) echo "panic: open $c" >&2; exit 2 ;;
wait) echo 7 >"$pid"; echo "guest out"; echo "guest err" >&2; fail "waiting on pid 7: $c" 1 ;;
*) echo 7 >"$pid"; echo "guest out"; echo "guest err" >&2; exit 3 ;;
esac
