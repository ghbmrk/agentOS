#!/bin/sh
# Build the camera decoder's stream root (CAM-clerk b2, NET-2): the static agentos-camdecode, linked
# with the pinned libavcodec (its H.264 decoder only, image/libavcodec.sh), and empty mount points,
# nothing else. The camera clerk runs it read-only in one long-running sandbox per streaming camera
# (gvisor.Stream.Root). Its own script, so image/build.sh keeps no build tag: the libavcodec tag
# applies to this cgo binary alone (TestImageBuildShipsTheUntaggedBuild).
#
# Usage: camdecode.sh ROOT LICENSES WORK
# Builds libavcodec in WORK (a fixed path keeps the build reproducible) and removes it after.
# Writes ROOT/agentos-camdecode, ROOT/{proc,dev,sys} and libavcodec's licence text at
# LICENSES/libavcodec/COPYING.LGPLv2.1. Needs what libavcodec.sh needs, plus Go, pkg-config and cc
# with a static libc.
#
# What the decoder links is pinned beyond h264.go's #cgo lines (TestDecoderCgoIsPinned; NET-2,
# #3816): the build stops unless go env gives cgo exactly the default tools and flags, whatever the
# caller's environment or go env file sets; unless pkg-config gives exactly the pinned flags for
# libavcodec and libavutil, private ones included; and unless the link map's cross-reference table
# shows no network call (linkfaults) defined or used by any file outside libc.a. libc's own static
# start-up references socket, bind and sendto (pthread_create's resolver state); nothing else may.
# A change to any pinned value here needs a NET-2 review.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
ROOT=$(realpath -m "$1"); LICENSES=$(realpath -m "$2"); lib=$(realpath -m "$3")

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

mkdir -p "$ROOT/proc" "$ROOT/dev" "$ROOT/sys"
sh "$HERE/libavcodec.sh" "$lib"
export PKG_CONFIG_PATH="$lib/opt/agentos-libavcodec/lib/pkgconfig" PKG_CONFIG_SYSROOT_DIR="$lib"
# go env CC CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_FFLAGS CGO_LDFLAGS PKG_CONFIG, Go's defaults.
env_pin='gcc
-O2 -g

-O2 -g
-O2 -g
-O2 -g
pkg-config'
[ "$(cd "$REPO/broker" && go env CC CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_FFLAGS CGO_LDFLAGS PKG_CONFIG)" = "$env_pin" ] ||
	{ echo "agentos-camdecode: go env sets other cgo tools or flags" >&2; exit 1; }
for f in --cflags --libs '--libs --static'; do
	case $f in --cflags) want="-I$lib/opt/agentos-libavcodec/include" ;;
	*) want="-L$lib/opt/agentos-libavcodec/lib -lavcodec -lavutil -lm -latomic" ;; esac
	# shellcheck disable=SC2046,SC2086 # word-split both: pkg-config spaces its output loosely
	[ "$(echo $(pkg-config $f libavcodec libavutil))" = "$want" ] ||
		{ echo "agentos-camdecode: pkg-config $f libavcodec libavutil is not the pinned set" >&2; exit 1; }
done
(cd "$REPO/broker" && CGO_ENABLED=1 go build -tags libavcodec,netgo,osusergo -trimpath \
	-ldflags="-s -w -buildid= -linkmode=external '-extldflags=-static -Wl,-Map=$lib/camdecode.map,--cref'" \
	-o "$ROOT/agentos-camdecode" ./cmd/agentos-camdecode)
faults=$(linkfaults "$lib/camdecode.map")
[ -z "$faults" ] || { printf 'agentos-camdecode links a network call:\n%s\n' "$faults" >&2; exit 1; }
! readelf -l "$ROOT/agentos-camdecode" | grep -q INTERP || { echo "agentos-camdecode is not static" >&2; exit 1; }
chmod 0755 "$ROOT/agentos-camdecode"
install -D -m 0644 "$lib/opt/agentos-libavcodec/share/COPYING.LGPLv2.1" "$LICENSES/libavcodec/COPYING.LGPLv2.1"
rm -rf "$lib"
