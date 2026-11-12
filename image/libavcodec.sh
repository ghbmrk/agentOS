#!/bin/sh
# Build the pinned libavcodec that agentos-camdecode links (CAM-clerk part b2, #3514): FFmpeg's
# release tarball, checked by hash, configured with the H.264 decoder alone (no other codec,
# parser, demuxer, filter, device, hardware path, thread, network or assembly), static, LGPL
# (no --enable-gpl). See NOTICE.
#
# Usage: libavcodec.sh BASE DIR    (as root)
# BASE is a root from image/guest-base.sh; DIR, a fixed path /tmp/agentos-NAME inside it, is
# created afresh. Unpacked, configured and compiled inside BASE by chroot with a clean environment,
# by BASE's tar, xz, make and gcc against its static libc, all from the image's pinned apt sources
# (IMG-camdecode-toolchain, #5582), never the build host's: two runners on different runner images
# would otherwise compile different bytes. Installs the headers, static libraries and licence text
# (share/COPYING.LGPLv2.1) under BASE/DIR/opt/agentos-libavcodec. Build in BASE with
#   PKG_CONFIG_PATH=DIR/opt/agentos-libavcodec/lib/pkgconfig PKG_CONFIG_SYSROOT_DIR=DIR
# and the Go build tag libavcodec. FFMPEG_TARBALL=<file> uses a local copy (still hash-checked).
# image/camdecode.sh pins the pkg-config flags this build installs: a configure change that alters
# them stops the image build until the pin there changes, under a NET-2 review (#3816).
# Needs on the host: chroot, sha256sum and curl (unless FFMPEG_TARBALL is set).
#
# The tarball is signed by the FFmpeg release signing key FCF9 86EA 15E6 E293 A564 4F10 B432 2F04
# D676 58D8 (checked when the pin was set); the hash pins exactly that file. The Ubuntu archive
# copy is the same file (Debian's orig tarball is upstream's, as its signature shows).
set -eu
FFMPEG=9.0.2
FFMPEG_SHA256=8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e
FFMPEG_URLS="https://ffmpeg.org/releases/ffmpeg-$FFMPEG.tar.xz
http://archive.ubuntu.com/ubuntu/pool/universe/f/ffmpeg/ffmpeg_$FFMPEG.orig.tar.xz"

[ $# -eq 2 ] || { echo "usage: libavcodec.sh BASE DIR" >&2; exit 2; }
base=$1 dir=$2
case $dir in /tmp/agentos-*/* | *..*) dir= ;; /tmp/agentos-?*) ;; *) dir= ;; esac
[ -n "$dir" ] || { echo "libavcodec.sh: DIR must be /tmp/agentos-NAME" >&2; exit 2; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
if [ -n "${FFMPEG_TARBALL:-}" ]; then
	cp "$FFMPEG_TARBALL" "$work/ffmpeg.tar.xz"
else
	for u in $FFMPEG_URLS; do curl -fsSLo "$work/ffmpeg.tar.xz" "$u" && break; done
fi
echo "$FFMPEG_SHA256  $work/ffmpeg.tar.xz" | sha256sum -c --quiet - || { echo "ffmpeg tarball hash" >&2; exit 1; }
rm -rf "${base:?}$dir"
mkdir -p "$base$dir/src"

# Only BASE's tools run from here; the tarball reaches its tar on stdin from the very file checked
# above. A fixed prefix, so the configuration string compiled into the library is the same on every
# build (image reproducibility); DESTDIR places it.
chroot "$base" /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent sh -ec 'cd "$1/src"
	tar -xJf - --strip-components=1
	./configure --prefix=/opt/agentos-libavcodec --enable-static --disable-shared \
		--disable-everything --enable-decoder=h264 \
		--disable-programs --disable-doc --disable-avdevice --disable-avformat --disable-avfilter \
		--disable-swscale --disable-swresample --disable-network --disable-autodetect \
		--disable-pthreads --disable-x86asm --disable-inline-asm --disable-debug >/dev/null
	make -j"$(nproc)" >/dev/null
	make install DESTDIR="$1" >/dev/null
	install -D -m 0644 COPYING.LGPLv2.1 "$1/opt/agentos-libavcodec/share/COPYING.LGPLv2.1"
	cd /
	rm -rf "$1/src"' sh "$dir" <"$work/ffmpeg.tar.xz"
