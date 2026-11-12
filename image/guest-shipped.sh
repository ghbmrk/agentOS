#!/bin/sh
# Which of the guest base's Debian packages the guests ship (IMG-guest-vulncheck, #5572), so the
# image vulnerability check scans exactly those. image/guest-base.sh's root also holds the toolchain
# that compiles the Codex worker's bwrap and the rest of Debian's essential set, none of which a
# guest carries; its full list stays in the manifest for the reproduce job.
#
# Usage: guest-shipped.sh BASE PATH...        (append the package that owns each PATH, a path in
#                                             BASE, to the file GUEST_SHIPPED names; fails on a
#                                             path no package owns, or one that resolves outside
#                                             BASE)
#        guest-shipped.sh --status BASE DIR   (write DIR/agentos.dpkg-status, the dpkg status of
#                                             every package in GUEST_SHIPPED, and
#                                             DIR/agentos.os-release, the inputs tools/vulncheck.py
#                                             image scans as the "image/guest" tree; fails when
#                                             the file is empty)
# GUEST_SHIPPED must be set: a guest build that records nothing would ship unscanned packages.
# The record is a file of the caller's, not one in BASE, which a guest build may only read.
# image/guest-userland.sh records every file it copies into a guest; guest/codex/build-rootfs.sh
# records every file the linker read into its static bwrap. image/build.sh writes the status once
# both guests are built.
set -eu
fail() { echo "guest-shipped.sh: $*" >&2; exit 1; }
shipped=${GUEST_SHIPPED:?set GUEST_SHIPPED to the file that records the packages the guests ship (#5572)}
if [ "${1:-}" = --status ]; then
	[ $# -eq 3 ] || { echo "usage: guest-shipped.sh --status BASE DIR" >&2; exit 2; }
	base=$2 dir=$3
	[ -s "$shipped" ] || fail "$shipped: no package recorded; the guests ship nothing from the base?"
	mkdir -p "$dir"
	# shellcheck disable=SC2046  # one package name per word
	dpkg-query --admindir="$base/var/lib/dpkg" -s $(sort -u "$shipped") >"$dir/agentos.dpkg-status"
	cp "$base/usr/lib/os-release" "$dir/agentos.os-release"
	exit 0
fi
[ $# -ge 2 ] || { echo "usage: guest-shipped.sh BASE PATH..." >&2; exit 2; }
base=$(cd "$1" && pwd -P)
shift
for p in "$@"; do
	r=$(readlink -f "$base$p") || fail "$p: unresolvable in $base"
	case $r in "$base"/*) ;; *) fail "$p resolves to $r, outside $base" ;; esac
	f=${r#"$base"}
	# "pkg[:arch][, pkg...]: PATH" for each owner; diversion lines name no owner.
	owners=$(dpkg-query --admindir="$base/var/lib/dpkg" -S "$f" 2>/dev/null |
		awk -v f=": $f" '!/^diversion by / && length($0) > length(f) && substr($0, length($0) - length(f) + 1) == f {
			print substr($0, 1, length($0) - length(f)) }' | tr ',' '\n' | sed 's/^ *//; s/:.*$//')
	[ -n "$owners" ] || fail "$f ($p): no Debian package in $base owns it, so its vulnerabilities could not be scanned"
	printf '%s\n' "$owners" >>"$shipped"
done
