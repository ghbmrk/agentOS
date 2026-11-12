#!/bin/sh
# One Debian security archive per build (IMG-repro-security-pin, #5021). The main archive is pinned
# by mkosi.conf's Mirror=; debian-security is read from one snapshot.debian.org timestamp, chosen
# once, so the image, its initrd and the guest roots, and image.yml's builds a and b, all install the
# same security packages, and each run still takes the security fixes published before it starts.
#
# Usage: security-snapshot.sh resolve
#          print the timestamp of the debian-security mirror run before the newest (a snapshot that never
#          changes, and whose import has finished)
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
# run_at TIME: the timestamp of the last debian-security mirror run at or before TIME. Asked for a time
# between two runs, snapshot.debian.org redirects to the earlier run's own timestamp. curl does not
# follow the redirect, it only reports where it points, and retries the 5xx answers the snapshot
# mirror gives for minutes at a time (#4518). The trailing "." keeps a newline the answer ends in,
# which $(...) would drop. Nothing the mirror sent is printed unless it is exactly a snapshot URL (#4648).
run_at() {
	loc=$(curl -q --proto '=https' -fsS -o /dev/null -w '%{redirect_url}.' --retry 8 --retry-max-time 600 \
		--max-time 60 "$archive/$1/")
	loc=${loc%.}; at=${loc#"$archive/"}; at=${at%/}
	if ! is_ts "$at" || [ "$loc" != "$archive/$at/" ]; then
		echo "security-snapshot.sh: snapshot.debian.org did not redirect to a debian-security snapshot" >&2
		exit 1
	fi
	echo "$at"
}
case "${1-}" in
resolve)
	[ $# -eq 1 ] || usage
	# The mirror run before the newest: the newest may still be importing, its InRelease served before
	# its Packages (#5606: a run resolved a minute after it started answered 404 for Packages).
	# Imports into one archive run one after another, so the run before it is whole; the build still
	# takes every security fix published up to that run, a few hours before it starts.
	newest=$(run_at "$(date -u +%Y%m%dT%H%M%SZ)")
	iso=$(echo "$newest" | sed 's/^\(....\)\(..\)\(..\)T\(..\)\(..\)\(..\)Z$/\1-\2-\3 \4:\5:\6 UTC/')
	ts=$(run_at "$(date -u -d "$iso - 1 second" +%Y%m%dT%H%M%SZ)")
	# And it must serve the index apt reads first, or the build would fail later with less to go on.
	curl -q --proto '=https' -fsS -o /dev/null --retry 8 --retry-max-time 600 --max-time 120 \
		"$archive/$ts/dists/trixie-security/main/binary-amd64/Packages.xz" || {
		echo "security-snapshot.sh: the debian-security snapshot $ts has no trixie-security Packages.xz" >&2
		exit 1
	}
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
