#!/bin/sh
# Build the AgentOS device image (PLAN P2-1). Run as root on Linux with network access to
# snapshot.debian.org, security.debian.org, storage.googleapis.com (gVisor), nodejs.org and
# registry.npmjs.org (OpenClaw guest), and the Go module proxy. CI does this: .github/workflows/image.yml
# Needs mkosi v24.3 (MKOSI=/path/to/mkosi), Go, mtools, erofs-utils, dosfstools, cryptsetup-bin,
# debian-archive-keyring.
#
# Usage: build.sh [OUT [VERSION]]
# Output in OUT: agentos_VERSION.raw (the whole drive), the release (agentos_VERSION.usr.raw,
# .usr-verity.raw, the boot entry, .release.json), the package manifest, and SHA256SUMS.
#
# Reproducibility: every input is pinned (Debian snapshot, gVisor and Node by hash, OpenClaw by
# lockfile, Go with -trimpath), file times are clamped to the commit time, and partition and
# file-system IDs come from mkosi.conf's Seed, so two builds of one commit give the same /usr
# root hash. VERSION defaults to the commit time, so releases sort in commit order.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
OUT=$(realpath -m "${1:-$HERE/out}"); MKOSI=${MKOSI:-mkosi}
SOURCE_DATE_EPOCH=$(git -c safe.directory="$REPO" -C "$REPO" log -1 --format=%ct); export SOURCE_DATE_EPOCH
VERSION=${2:-$(TZ=UTC git -c safe.directory="$REPO" -C "$REPO" log -1 --date=format-local:%Y%m%d.%H%M%S --format=%cd)}
GVISOR=release-20260928.0
GVISOR_SHA512=c8d3a9fd4d4c4f5b8ff213caa4517356be128d18659ec4cde37828fe797f61a9725a602a846c81a8ed19c057a996515d31c081eba343ed4613a89951ba32ed59

mkdir -p "$OUT"
STAGE=$OUT/stage; rm -rf "$STAGE"; mkdir -p "$STAGE/usr/lib/agentos/images"

# The broker and the vault process, static and path-free.
for cmd in agentosd agentos-egress; do
	(cd "$REPO/broker" && CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= \
		-o "$STAGE/usr/lib/agentos/$cmd" "./cmd/$cmd")
done

# gVisor, the same release and hash as CI's machine tests.
curl -fsSLo "$OUT/gvisor.tar.bz2" \
	"https://storage.googleapis.com/gvisor/releases/release/${GVISOR#release-}/x86_64/gvisor.tar.bz2"
echo "$GVISOR_SHA512  $OUT/gvisor.tar.bz2" | sha512sum -c -
mkdir -p "$OUT/gvisor" && tar -xjf "$OUT/gvisor.tar.bz2" -C "$OUT/gvisor"
install -m 0755 "$OUT/gvisor/runsc" "$STAGE/usr/lib/agentos/runsc"
rm -rf "$OUT/gvisor.tar.bz2" "$OUT/gvisor"

# The OpenClaw guest's root file system (P1-7), as an agent-machine image.
sh "$REPO/guest/openclaw/build-rootfs.sh" "$STAGE/usr/lib/agentos/images/openclaw"
# How agentosd starts the agent machine (W1): its -agent-launch default.
install -D -m 0644 "$REPO/guest/openclaw/launch.json" "$STAGE/usr/lib/agentos/guest/launch.json"
chmod -R u+w,go-w "$STAGE"

$MKOSI -C "$HERE/mkosi" -f --image-version="$VERSION" --extra-tree="$STAGE:/" --output-dir "$OUT" build
python3 "$HERE/finish_image.py" "$OUT" "$VERSION"
rm -rf "$STAGE"
( cd "$OUT" && sha256sum "agentos_$VERSION.raw" "agentos_$VERSION.usr.raw" "agentos_$VERSION.usr-verity.raw" \
	"agentos_$VERSION+3.conf" "agentos_$VERSION.release.json" > SHA256SUMS && cat SHA256SUMS )
