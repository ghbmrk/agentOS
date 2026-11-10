#!/bin/sh
# ci_boot.sh's check of the WAN's router-advertisement handling (#5189, #5330, ENF-l-21), in two halves.
#  ci_wan.sh probe        In the guest, before the boot report (ci_boot.sh hands this file over in a
#                         credential drop-in): reads the first network card, standing in for the WAN,
#                         for up to 60 s and prints one "enforcer-ci: wan=..." line.
#  ci_wan.sh verdict LOG  On the host: reads that line from the console log and prints ok or MISS;
#                         exits 1 on MISS.
# With forwarding on the kernel ignores accept_ra=1, and the daemon holds default.accept_ra=0, so the
# WAN takes router advertisements only when its link configuration says so: sysctl.d accept_ra=2 on
# it, or networkd's IPv6AcceptRA= (networkd then handles them itself and the WAN gets an IPv6 default
# route from QEMU's). A link left down passes only while the daemon unit is the placeholder, when
# nothing configures any interface (ENF-m-7): its effective ExecStart, drop-ins applied, is the one
# command /usr/bin/sleep infinity. A real daemon in that unit, however its Description reads, is
# held to the check. R prefixes /sys and /proc; only test_ci_wan.py sets it.

probe() {
	n=none; i=0
	for d in "$R"/sys/class/net/*; do [ -e "$d/device" ] && { n=${d##*/}; break; }; done
	daemon=real; x=$(systemctl show -P ExecStart agentos-enforcer.service 2>/dev/null) || x=
	[ "$(printf '%s\n' "$x" | wc -l)" = 1 ] &&
		case $x in '{ path=/usr/bin/sleep ; argv[]=/usr/bin/sleep infinity ; '*) daemon=placeholder ;; esac
	while :; do
		up=$(cat "$R/sys/class/net/$n/operstate"); ra=$(cat "$R/proc/sys/net/ipv6/conf/$n/accept_ra")
		fw=$(cat "$R/proc/sys/net/ipv6/conf/$n/forwarding")
		route=no; grep -q "^0\{32\} 00 .* $n\$" "$R/proc/net/ipv6_route" && route=yes
		[ "$ra" = 2 ] || [ $route = yes ] || [ $i -ge 60 ] || { [ $daemon = placeholder ] && [ "$up" != up ]; } && break
		i=$((i + 1)); sleep 1
	done
	echo "enforcer-ci: wan=$n operstate=$up accept_ra=$ra forwarding=$fw ipv6_default=$route daemon=$daemon"
}

verdict() {
	wan=$(grep -ao 'enforcer-ci: wan=[^ ]* operstate=[^ ]* accept_ra=[^ ]* forwarding=[^ ]* ipv6_default=[^ ]* daemon=[a-z]*' \
		"$1" | head -n 1 | sed 's/^enforcer-ci: //')
	m="MISS WAN router advertisements handled:"
	case " $wan " in
	"  " | " wan=none "*) echo "MISS the WAN probe's line on a network card ($wan)"; return 1 ;;
	*" accept_ra=2 "* | *" ipv6_default=yes "*) echo "ok   WAN router advertisements handled ($wan)" ;;
	*" operstate=up "*) echo "$m accept_ra=2 or an IPv6 default route ($wan)"; return 1 ;;
	*" daemon=placeholder ") echo "ok   no WAN link configured until ENF-m-b ($wan)" ;;
	*" operstate=down "*) echo "$m the WAN is down ($wan)"; return 1 ;;
	*" operstate=unknown "*) echo "$m the WAN's link state is unknown ($wan)"; return 1 ;;
	*) echo "$m the WAN's link is not up ($wan)"; return 1 ;;
	esac
}

case ${1:-} in
probe) probe ;;
verdict) verdict "$2" ;;
*) echo "usage: ci_wan.sh probe | ci_wan.sh verdict LOG" >&2; exit 2 ;;
esac
