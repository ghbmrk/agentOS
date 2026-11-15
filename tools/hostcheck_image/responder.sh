# shellcheck shell=sh
# hostcheck's liveness responder in the agentOS image (HOST-1e2; HOST-1h part 2). Runs as
# agentos-hostcheck-responder.service; tools/hostcheck.py passes the unit and this script as SMBIOS
# credentials (tests/test_hostcheck.py IMAGE_CREDENTIALS), so the shipped image holds neither.
# It reads command lines from its console (ttyS0):
#   alive NONCE       print HOSTCHECK-ALIVE NONCE: hostcheck's power cut waits for it
#   poweroff | reboot ask systemd for that orderly exit, and keep answering
# It never stops itself, and it ignores SIGTERM, so it answers into a shutdown until the unit's stop
# timeout kills it: only that stop ends the answers, and the unit is ordered so that the stop comes
# before agentos-mor.service's ExecStop clears MOR. The image-in-shutdown test holds that.
trap '' TERM
stty -echo 2>/dev/null
echo HOSTCHECK-READY
while read -r cmd arg; do
	case $cmd in
	alive) echo "HOSTCHECK-ALIVE $arg" ;;
	poweroff | reboot) systemctl --no-block "$cmd" || echo "HOSTCHECK-EXIT-FAILED $cmd" ;;
	esac
done
