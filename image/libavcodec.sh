#!/bin/sh
# Build the pinned libavcodec that agentos-camdecode links (CAM-clerk part b2, #3514): FFmpeg's
# release tarball, checked by hash, configured with the H.264 decoder alone (no other codec,
# parser, demuxer, filter, device, hardware path, thread, network or assembly), static, LGPL
# (no --enable-gpl). See NOTICE.
#
# Usage: libavcodec.sh DESTDIR
# Installs the headers, static libraries and licence text (share/COPYING.LGPLv2.1) under
# DESTDIR/opt/agentos-libavcodec. Build with
#   PKG_CONFIG_PATH=DESTDIR/opt/agentos-libavcodec/lib/pkgconfig PKG_CONFIG_SYSROOT_DIR=DESTDIR
# and the Go build tag libavcodec. FFMPEG_TARBALL=<file> uses a local copy (still hash-checked).
# image/camdecode.sh pins the pkg-config flags this build installs: a configure change that alters
# them stops the image build until the pin there changes, under a NET-2 review (#3816).
# Needs: curl (unless FFMPEG_TARBALL is set), sha256sum, tar, xz, make, cc.
#
# The tarball is signed by the FFmpeg release signing key FCF9 86EA 15E6 E293 A564 4F10 B432 2F04
# D676 58D8 (checked when the pin was set); the hash pins exactly that file. The Ubuntu archive
# copy is the same file (Debian's orig tarball is upstream's, as its signature shows).
set -eu
FFMPEG=9.0.2
FFMPEG_SHA256=8c3850283eb25fa026482078a04051e0be17347b09ef81a0849bec15a96e002e
FFMPEG_URLS="https://ffmpeg.org/releases/ffmpeg-$FFMPEG.tar.xz
http://archive.ubuntu.com/ubuntu/pool/universe/f/ffmpeg/ffmpeg_$FFMPEG.orig.tar.xz"

DEST=$(realpath -m "$1"); mkdir -p "$DEST"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
if [ -n "${FFMPEG_TARBALL:-}" ]; then
	cp "$FFMPEG_TARBALL" "$work/ffmpeg.tar.xz"
else
	for u in $FFMPEG_URLS; do curl -fsSLo "$work/ffmpeg.tar.xz" "$u" && break; done
fi
echo "$FFMPEG_SHA256  $work/ffmpeg.tar.xz" | sha256sum -c --quiet - || { echo "ffmpeg tarball hash" >&2; exit 1; }
tar -xJf "$work/ffmpeg.tar.xz" -C "$work"

# A fixed prefix, so the configuration string compiled into the library is the same on every
# build (image reproducibility); DESTDIR places it.
cd "$work/ffmpeg-$FFMPEG"
./configure --prefix=/opt/agentos-libavcodec --enable-static --disable-shared \
	--disable-everything --enable-decoder=h264 \
	--disable-programs --disable-doc --disable-avdevice --disable-avformat --disable-avfilter \
	--disable-swscale --disable-swresample --disable-network --disable-autodetect \
	--disable-pthreads --disable-x86asm --disable-inline-asm --disable-debug >/dev/null
make -j"$(nproc)" >/dev/null
make install DESTDIR="$DEST" >/dev/null
install -D -m 0644 COPYING.LGPLv2.1 "$DEST/opt/agentos-libavcodec/share/COPYING.LGPLv2.1"
