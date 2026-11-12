#!/bin/sh
# The guest roots' Debian userland (IMG-reproduce-pcre2, #5570): an essential Debian root plus
# libstdc++6 (Node's), installed from the image's own apt sources (the pinned snapshot and
# trixie-security, mkosi.pkgmngr's mkosi.sources, or SOURCES below), so the shell, tools and libraries the OpenClaw
# and Codex roots carry never come from the build host. Two runners on different runner images
# built different guest bytes from their own copies (#5570: libpcre2-8.so.0); image/guest-userland.sh
# copies from this root instead. The Codex worker's static bwrap (IMG-guest-bwrap-toolchain, #5571)
# and the camera decoder with its libavcodec (IMG-camdecode-toolchain, #5582) are unpacked, patched
# and compiled inside this root too, by its tar, xz, patch, make, pkg-config and gcc against
# libc6-dev's and libcap-dev's static libraries, never the build host's. No guest carries the
# toolchain, but it decides those binaries' bytes, so its packages are in the manifest as well.
#
# Usage: guest-base.sh ROOT MANIFEST [SOURCES]    (as root; needs mmdebstrap and debian-archive-keyring)
# ROOT is created afresh. MANIFEST gets the root's packages in mkosi's manifest shape, so the
# reproduce job's compare_manifests.py names any package two builds read differently. SOURCES is the
# apt sources file to install from: image/build.sh passes the one it gives mkosi, its security stanza
# on the build's one debian-security snapshot (image/security-snapshot.sh, #5021), so both guest
# roots take the image's security packages; without it, mkosi.sources as committed.
set -eu
[ $# -eq 2 ] || [ $# -eq 3 ] || { echo "usage: guest-base.sh ROOT MANIFEST [SOURCES]" >&2; exit 2; }
root=$1 manifest=$2
sources=${3:-$(cd "$(dirname "$0")" && pwd)/mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources}
# snapshot.debian.org answers 503/504 for minutes at a time (#4518). Each attempt starts from an
# empty root and reads the same signed sources, as ci.yml's image-tools step does; --one-file-system
# because a killed attempt may leave the root's /dev or /proc mounted.
for wait in 15 30 60 last; do
	rm -rf --one-file-system "$root"
	err=0
	timeout 240 mmdebstrap --mode=root --variant=essential --include=libstdc++6,gcc,libc6-dev,libcap-dev,make,pkgconf,xz-utils,patch trixie "$root" "$sources" || err=$?
	[ "$err" -ne 0 ] || break
	[ "$wait" != last ] || exit "$err"
	echo "guest-base.sh: mmdebstrap exited $err (snapshot.debian.org outage?); retrying in ${wait}s" >&2
	sleep "$wait"
done
dpkg-query --admindir="$root/var/lib/dpkg" -W libpcre2-8-0 libc6 libstdc++6 bash coreutils dash gcc libc6-dev libcap-dev make pkgconf xz-utils patch
mkdir -p "$(dirname "$manifest")"
dpkg-query --admindir="$root/var/lib/dpkg" -W -f '${Package}\t${Version}\t${Architecture}\n' |
	python3 -I -c 'import json, sys
rows = sorted(l.rstrip("\n").split("\t") for l in sys.stdin if l.strip())
json.dump({"packages": [{"name": n, "version": v, "architecture": a} for n, v, a in rows]}, sys.stdout, indent=1)
print()' >"$manifest"
