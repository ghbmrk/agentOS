# shellcheck shell=sh
# hostcheck's liveness responder in the agentOS image (HOST-1e2; HOST-1h part 2). Runs as
# hostcheck-responder.service; tools/hostcheck.py passes the unit and this script as SMBIOS
# credentials (tests/test_hostcheck.py IMAGE_CREDENTIALS), so the shipped image holds neither.
# It reads command lines from its console (ttyS0):
#   alive NONCE       print HOSTCHECK-ALIVE NONCE: hostcheck's power cut waits for it
#   poweroff | reboot ask systemd for that orderly exit, and keep answering
# It never stops itself, and it outlives SIGTERM, so it answers into a shutdown until the unit's stop
# timeout kills it: only that stop ends the answers, and the unit is ordered so that the stop comes
# before agentos-mor.service's ExecStop clears MOR. The image-in-shutdown test holds that.
# At its start and at SIGTERM it prints HOSTCHECK-DIAG lines: what the MOR clear will find (its
# unit's state, MOR, the directories the clear refuses on while they hold files) and the clear's
# journal, this boot's and the last one's, so a phase that finds MOR set says why on the console.
MOR=/sys/firmware/efi/efivars/MemoryOverwriteRequestControl-e20939be-32d4-41be-a150-897f85d49829
diag() {
	echo "HOSTCHECK-DIAG $1 agentos-mor.service $(systemctl show -p ActiveState -p SubState -p Result --value agentos-mor.service | tr '\n' ' ')"
	echo "HOSTCHECK-DIAG $1 mor $(od -An -tu1 -v "$MOR" 2>&1 | tr -s ' \n' ' ')"
	for d in /run/agentos-setup /run/agentos-link-capture; do
		echo "HOSTCHECK-DIAG $1 $d $(ls -A "$d" 2>&1 | tr '\n' ' ')"
	done
	for b in 0 -1; do
		journalctl -q -b "$b" -u agentos-mor.service -o cat 2>&1 | tail -n 5 | sed "s/^/HOSTCHECK-DIAG $1 journal $b: /"
	done
	# The last boot's last answers and its MOR clear on one clock (the journal's monotonic stamps), for
	# the image-in-shutdown test: the console shows no agentos-mor line, so it reads the order here.
	journalctl -q -b -1 -o short-monotonic -t hostcheck-responder -t agentos-mor 2>&1 | tail -n 4 |
		sed "s/^/HOSTCHECK-DIAG $1 order: /"
}
# A trapped SIGTERM ends a pending read, so the loop below resumes reading after one; only end of
# input with no SIGTERM since ends it.
stopping=
trap 'stopping=1; diag stop' TERM
stty -echo 2>/dev/null
diag start
echo HOSTCHECK-READY
while :; do
	while read -r cmd arg; do
		case $cmd in
		alive)
			echo "HOSTCHECK-ALIVE $arg"
			echo "HOSTCHECK-ALIVE $arg" | systemd-cat -t hostcheck-responder 2>/dev/null ;;
		# The request starts the stop of this unit, whose SIGTERM reaches the whole cgroup, so it can
		# kill systemctl before it reads systemd's answer: systemctl runs with SIGTERM ignored, and
		# fails only on a refusal (HOST-restart-flake, #5992). The trap above would reset it.
		poweroff | reboot) (trap '' TERM; exec systemctl --no-block "$cmd") || echo "HOSTCHECK-EXIT-FAILED $cmd" ;;
		esac
	done
	[ -n "$stopping" ] || exit 0
	stopping=
done
