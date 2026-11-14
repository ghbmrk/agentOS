#!/bin/sh
# Build the camera decoder's stream root (CAM-clerk b2, NET-2): the static agentos-camdecode, linked
# with the pinned libavcodec (its H.264 decoder only, image/libavcodec.sh), and empty mount points,
# nothing else. The camera clerk runs it read-only in one long-running sandbox per streaming camera
# (gvisor.Stream.Root). Its own script, so image/build.sh keeps no build tag: the libavcodec tag
# applies to this cgo binary alone (TestImageBuildShipsTheUntaggedBuild).
#
# Usage: camdecode.sh ROOT LICENSES    (as root, with GUEST_BASE and GUEST_SHIPPED set)
# Writes ROOT/agentos-camdecode, ROOT/{proc,dev,sys} and libavcodec's licence text at
# LICENSES/libavcodec/COPYING.LGPLv2.1. Both libavcodec and the decoder are built inside GUEST_BASE,
# a root from image/guest-base.sh, at a fixed path (reproducibility) removed after, by chroot with a
# clean environment (IMG-camdecode-toolchain, #5582): cgo's gcc, the static libc and pkg-config are
# the base's, from the image's pinned apt sources, never the build host's, and no host tar, xz or
# patch runs. The build host gives only Go: the toolchain broker/go.mod pins (go env GOROOT) and the
# module's source, copied in. Needs what libavcodec.sh needs, plus Go.
#
# The decoder carries the code of every archive and object its link read from the base: libc6-dev's
# libc.a and start-up files, libgcc's. Each input the link map loads from outside $lib is recorded
# as shipped (image/guest-shipped.sh, #5599), so the image vulnerability check scans its Debian
# package. Go's and cgo's own objects stay under $lib: the jail's TMPDIR is there.
#
# What the decoder links is pinned beyond h264.go's #cgo lines (TestDecoderCgoIsPinned; NET-2,
# #3816): the build stops unless go env gives cgo exactly the default tools and flags; unless
# pkg-config gives exactly the pinned flags for libavcodec and libavutil, private ones included; and
# unless the link map's cross-reference table shows no network call (linkfaults) defined or used by
# any file outside libc.a. libc's own static start-up references socket, bind and sendto
# (pthread_create's resolver state); nothing else may. A change to any pinned value here needs a
# NET-2 review.
set -eu
# A go.work in the repo would override broker/go.mod, go.sum and vendor/ (#4007 Security).
export GOWORK=off
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
ROOT=$(realpath -m "$1"); LICENSES=$(realpath -m "$2")
base=${GUEST_BASE:?set GUEST_BASE to a root from image/guest-base.sh}
: "${GUEST_SHIPPED:?set GUEST_SHIPPED to the file that records the packages the guests ship (#5572)}"
# The build's fixed path inside the base; every path the jail sees is under it.
lib=/tmp/agentos-camdecode

# linkfaults MAP: each network call in the cross-reference table of the link map MAP (ld -Map
# --cref) that a file outside libc.a defines or uses, one per line; a map without the table is a
# fault too. A table line starts with the symbol, then its defining file; the files using it
# follow, indented, one per line (a long symbol's file starts the next line).
linkfaults() {
	awk -v net='^(__libc_|_+)?(socket|socketpair|connect|bind|listen|accept4?|send|sendto|sendm?msg|recv|recvfrom|recvm?msg|getaddrinfo|getnameinfo|gethostby(name2?|addr)(_r)?|res_n?(query|search|send))$' '
		/^Cross Reference Table/ { t = 1; next }
		!t || /^Symbol / || NF == 0 { next }
		/^[^ \t]/ { sym = $1; if (NF < 2) next; f = $2 }
		/^[ \t]/ { f = $1 }
		sym ~ net && f !~ /\/libc\.a\(/ { print sym " in " f }
		END { if (!t) print "no cross-reference table" }
	' "$1"
}

# jail CMD...: CMD in the base's broker copy, by chroot with only these variables: the copied Go,
# no go env file, no download, no workspace, and pkg-config pointed at the pinned libavcodec.
jail() {
	chroot "$base" /usr/bin/env -i PATH="$lib/go/bin:/usr/bin:/bin" LC_ALL=C HOME=/nonexistent \
		GOROOT="$lib/go" GOCACHE="$lib/gocache" GOMODCACHE="$lib/gomodcache" GOENV=off GOTOOLCHAIN=local \
		GOPROXY=off GOWORK=off TMPDIR="$lib/tmp" \
		PKG_CONFIG_PATH="$lib/opt/agentos-libavcodec/lib/pkgconfig" PKG_CONFIG_SYSROOT_DIR="$lib" \
		sh -c 'cd "$0" && exec "$@"' "$lib/broker" "$@"
}

mkdir -p "$ROOT/proc" "$ROOT/dev" "$ROOT/sys"
trap 'rm -rf "${base:?}$lib"' EXIT
sh "$HERE/libavcodec.sh" "$base" "$lib"
goroot=$(cd "$REPO/broker" && go env GOROOT)
mkdir "$base$lib/go" "$base$lib/broker" "$base$lib/tmp"
cp -a "$goroot/." "$base$lib/go/"
cp -a "$REPO/broker/." "$base$lib/broker/"
# go env CC CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_FFLAGS CGO_LDFLAGS PKG_CONFIG, Go's defaults.
env_pin='gcc
-O2 -g

-O2 -g
-O2 -g
-O2 -g
pkg-config'
[ "$(jail go env CC CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_FFLAGS CGO_LDFLAGS PKG_CONFIG)" = "$env_pin" ] ||
	{ echo "agentos-camdecode: go env sets other cgo tools or flags" >&2; exit 1; }
for f in --cflags --libs '--libs --static'; do
	case $f in --cflags) want="-I$lib/opt/agentos-libavcodec/include" ;;
	*) want="-L$lib/opt/agentos-libavcodec/lib -lavcodec -lavutil -lm -latomic" ;; esac
	# shellcheck disable=SC2046,SC2086 # word-split both: pkg-config spaces its output loosely
	[ "$(echo $(jail pkg-config $f libavcodec libavutil))" = "$want" ] ||
		{ echo "agentos-camdecode: pkg-config $f libavcodec libavutil is not the pinned set" >&2; exit 1; }
done
(jail env CGO_ENABLED=1 go build -tags libavcodec,netgo,osusergo -trimpath \
	-ldflags="-s -w -buildid= -linkmode=external '-extldflags=-static -Wl,-Map=$lib/camdecode.map,--cref'" \
	-o "$lib/agentos-camdecode" ./cmd/agentos-camdecode)
faults=$(linkfaults "$base$lib/camdecode.map")
[ -z "$faults" ] || { printf 'agentos-camdecode links a network call:\n%s\n' "$faults" >&2; exit 1; }
# Each file the link loaded from outside $lib, by its LOAD line in the map ("LOAD linker stubs" names
# no file). A relative path is passed on too, and fails there, so no input goes unrecorded.
loaded=$(awk -v lib="$lib/" '/^LOAD / && $2 != "linker" && index($2, lib) != 1 { print $2 }' "$base$lib/camdecode.map" | sort -u)
[ -n "$loaded" ] || { echo "agentos-camdecode: the link map loads nothing from outside $lib" >&2; exit 1; }
# shellcheck disable=SC2086  # one path per word
sh "$HERE/guest-shipped.sh" "$base" $loaded
! jail readelf -l "$lib/agentos-camdecode" | grep -q INTERP || { echo "agentos-camdecode is not static" >&2; exit 1; }
install -m 0755 "$base$lib/agentos-camdecode" "$ROOT/agentos-camdecode"
install -D -m 0644 "$base$lib/opt/agentos-libavcodec/share/COPYING.LGPLv2.1" "$LICENSES/libavcodec/COPYING.LGPLv2.1"
