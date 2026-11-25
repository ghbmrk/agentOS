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
# With SHIPPED_FOR naming a built binary whose link read the PATHs, each owner is also recorded against
# that file's SHA-256 ("SHA256 PACKAGE" lines in GUEST_SHIPPED.inputs), and --status moves those lines to
# DIR/agentos.inputs: image/static_elf.py holds each static binary declared "linked" to them (#5885).
# With SHIPPED_BYTES=1 (image/guest-userland.sh, which ships each PATH as it is), each PATH's bytes must
# equal its dpkg md5sum for an owner, and "MD5 PACKAGE" is recorded for each such owner (GUEST_SHIPPED.md5sums,
# moved by --status to DIR/agentos.md5sums): image/static_elf.py holds a guest file declared "package" to
# them (#6482).
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
	if [ -f "$shipped.inputs" ]; then
		sort -u "$shipped.inputs" >"$dir/agentos.inputs"
		rm -f "$shipped.inputs"
	fi
	if [ -f "$shipped.md5sums" ]; then
		sort -u "$shipped.md5sums" >"$dir/agentos.md5sums"
		rm -f "$shipped.md5sums"
	fi
	exit 0
fi
[ $# -ge 2 ] || { echo "usage: guest-shipped.sh BASE PATH..." >&2; exit 2; }
base=$(cd "$1" && pwd -P)
shift
sum=
if [ -n "${SHIPPED_FOR:-}" ]; then
	[ -f "$SHIPPED_FOR" ] || fail "SHIPPED_FOR $SHIPPED_FOR: no such file"
	sum=$(sha256sum <"$SHIPPED_FOR" | cut -d' ' -f1)
fi
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
	[ -z "$sum" ] || printf '%s\n' "$owners" | sed "s/^/$sum /" >>"$shipped.inputs"
	[ "${SHIPPED_BYTES:-}" = 1 ] || continue
	md5=$(md5sum <"$r" | cut -d' ' -f1)
	held=
	for o in $owners; do
		# A Multi-Arch: same package's md5sums carry its architecture (libc6:amd64.md5sums).
		for m in "$base/var/lib/dpkg/info/$o.md5sums" "$base/var/lib/dpkg/info/$o":*.md5sums; do
			[ -f "$m" ] || continue
			if awk -v p="${f#/}" -v s="$md5" 'substr($0, 35) == p && substr($0, 1, 32) == s { ok = 1 } END { exit !ok }' "$m"; then
				printf '%s %s\n' "$md5" "$o" >>"$shipped.md5sums"
				held=1
			fi
		done
	done
	[ -n "$held" ] || fail "$f ($p): its bytes are not the ones dpkg installed (no owner's md5sums list MD5 $md5 at that path)"
done
