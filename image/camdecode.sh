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
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
ROOT=$(realpath -m "$1"); LICENSES=$(realpath -m "$2"); lib=$(realpath -m "$3")
mkdir -p "$ROOT/proc" "$ROOT/dev" "$ROOT/sys"
sh "$HERE/libavcodec.sh" "$lib"
(cd "$REPO/broker" && CGO_ENABLED=1 PKG_CONFIG_PATH="$lib/opt/agentos-libavcodec/lib/pkgconfig" \
	PKG_CONFIG_SYSROOT_DIR="$lib" go build -tags libavcodec,netgo,osusergo -trimpath \
	-ldflags='-s -w -buildid= -linkmode=external -extldflags=-static' \
	-o "$ROOT/agentos-camdecode" ./cmd/agentos-camdecode)
! readelf -l "$ROOT/agentos-camdecode" | grep -q INTERP || { echo "agentos-camdecode is not static" >&2; exit 1; }
chmod 0755 "$ROOT/agentos-camdecode"
install -D -m 0644 "$lib/opt/agentos-libavcodec/share/COPYING.LGPLv2.1" "$LICENSES/libavcodec/COPYING.LGPLv2.1"
rm -rf "$lib"
