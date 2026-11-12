#!/bin/sh
# One Debian security archive per build (IMG-repro-security-pin, #5021). The main archive is pinned
# by mkosi.conf's Mirror=; debian-security is read from one snapshot.debian.org timestamp, chosen
# once, so the image, its initrd and the guest roots, and image.yml's builds a and b, all install the
# same security packages, and each run still takes the security fixes published before it starts.
#
# Usage: security-snapshot.sh resolve
#          print the timestamp of the latest debian-security snapshot (a mirror run, which never changes)
#        security-snapshot.sh sources TIMESTAMP
#          print the image's apt sources (mkosi.pkgmngr's mkosi.sources) with the security stanza on
#          that snapshot; every other line is unchanged. Apt still checks the stanza's Valid-Until, so
#          a snapshot older than the security archive's expiry window (a week) is refused.
set -eu
usage() { echo "usage: security-snapshot.sh resolve | sources TIMESTAMP" >&2; exit 2; }
is_ts() {
	case $1 in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z) return 0 ;; esac
	return 1
}
archive=https://snapshot.debian.org/archive/debian-security
live='URIs: http://security.debian.org/debian-security'
case "${1-}" in
resolve)
	[ $# -eq 1 ] || usage
	# Asked for a time between two mirror runs, snapshot.debian.org redirects to the earlier run's own
	# timestamp; that is the pin. curl does not follow the redirect, it only reports where it points,
	# and retries the 5xx answers the snapshot mirror gives for minutes at a time (#4518).
	# The trailing "." keeps a newline the answer ends in, which $(...) would drop.
	loc=$(curl -q --proto '=https' -fsS -o /dev/null -w '%{redirect_url}.' --retry 8 --retry-max-time 600 \
		--max-time 60 "$archive/$(date -u +%Y%m%dT%H%M%SZ)/")
	loc=${loc%.}; ts=${loc#"$archive/"}; ts=${ts%/}
	# Nothing the mirror sent is printed unless it is exactly a snapshot URL (#4648).
	if ! is_ts "$ts" || [ "$loc" != "$archive/$ts/" ]; then
		echo "security-snapshot.sh: snapshot.debian.org did not redirect to a debian-security snapshot" >&2
		exit 1
	fi
	echo "$ts"
	;;
sources)
	[ $# -eq 2 ] && is_ts "$2" || usage
	src=$(cd "$(dirname "$0")" && pwd)/mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources
	[ "$(grep -cxF "$live" "$src")" = 1 ] || {
		echo "security-snapshot.sh: $src has no single live security stanza to pin" >&2
		exit 1
	}
	awk -v live="$live" -v pin="URIs: $archive/$2/" '$0 == live { $0 = pin } { print }' "$src"
	;;
*) usage ;;
esac
