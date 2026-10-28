#!/usr/bin/env bash
# Build the camera node image (CAM-node part c, #3513; briefs/CAM-node.md): Buildroot, pinned by
# hash, with the external tree in external/. BOARD is cm4 (the prototype, part d) or qemu (the
# end-to-end test's board, never shipped).
#
#	image/camnode/build.sh BOARD OUT [VERSION]
#
# CAMNODE_RELEASE_PUB names the release signer's Ed25519 public key (base64, one line; HW-10).
# A cm4 build needs it. A qemu build without it makes a throwaway test key in OUT/e2e, whose
# private half only the end-to-end driver reads. CAMNODE_BOOT_SIG optionally names the release
# signer's boot.sig over a boot.img from an earlier build of the same commit (post-image.sh).
# Downloads go to CAMNODE_DL (default OUT/dl) and compiler output to CAMNODE_CCACHE (default
# OUT/ccache), which CI caches. Outputs in OUT: camnode-BOARD.{disk.img,slot.img,slot.json,
# boot.img} and SHA256SUMS; the Buildroot tree stays in OUT/br.
set -euo pipefail
BOARD=${1:?usage: build.sh cm4|qemu OUT [VERSION]}
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
OUT=$(realpath -m "${2:?usage: build.sh cm4|qemu OUT [VERSION]}")
case $BOARD in cm4 | qemu) ;; *) echo "build.sh: BOARD is cm4 or qemu" >&2; exit 2 ;; esac
SOURCE_DATE_EPOCH=$(git -c safe.directory="$REPO" -C "$REPO" log -1 --format=%ct); export SOURCE_DATE_EPOCH
CAMNODE_VERSION=${3:-$SOURCE_DATE_EPOCH}; export CAMNODE_VERSION

# Buildroot's long-term release, checked against the SHA-256 in its signed release notice
# (buildroot-2026.02.3.tar.xz.sign, signed by Arnout Vandecappelle).
BR=buildroot-2026.02.3
BR_SHA256=5a59e7501b0b4ec52c41f4bfa79412320e0b37eae5f719605a258e8d0c6fc7fb

mkdir -p "$OUT"
DL=$(realpath -m "${CAMNODE_DL:-$OUT/dl}"); CCACHE=$(realpath -m "${CAMNODE_CCACHE:-$OUT/ccache}")
mkdir -p "$DL" "$CCACHE" "$OUT/stage"
if [ ! -f "$DL/$BR.tar.xz" ] || ! echo "$BR_SHA256  $DL/$BR.tar.xz" | sha256sum -c --status -; then
	curl -fsSLo "$DL/$BR.tar.xz.part" "https://buildroot.org/downloads/$BR.tar.xz"
	mv "$DL/$BR.tar.xz.part" "$DL/$BR.tar.xz"
fi
echo "$BR_SHA256  $DL/$BR.tar.xz" | sha256sum -c -
rm -rf "$OUT/$BR" && tar -xf "$DL/$BR.tar.xz" -C "$OUT"

# The node's one service, static, from this checkout (broker/cmd/agentos-camnode).
gobuild() { # OUTPUT PACKAGE-OR-FILE
	(cd "$REPO/broker" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath \
		-ldflags='-s -w -buildid=' -o "$1" "$2")
}
gobuild "$OUT/stage/agentos-camnode" ./cmd/agentos-camnode
export CAMNODE_BIN=$OUT/stage/agentos-camnode

if [ "$BOARD" = qemu ]; then
	# The end-to-end stand-ins, one file each, built inside the broker's module as
	# image/drivercheck is (image/build.sh): they import nothing outside the standard library.
	mkdir -p "$OUT/e2e"
	for s in element button encoder; do
		gobuild "$OUT/e2e/e2e-$s" "../image/camnode/e2e/$s/main.go"
	done
	export CAMNODE_E2E_DIR=$OUT/e2e
	if [ -z "${CAMNODE_RELEASE_PUB:-}" ]; then
		(cd "$REPO/broker" && CGO_ENABLED=0 go build -trimpath -o "$OUT/e2e/camnode-e2e" ../image/camnode/e2e/driver/*.go)
		"$OUT/e2e/camnode-e2e" keygen "$OUT/e2e/release"
		CAMNODE_RELEASE_PUB=$OUT/e2e/release.pub
	fi
fi
: "${CAMNODE_RELEASE_PUB:?a cm4 build needs CAMNODE_RELEASE_PUB, the release signer public key}"
CAMNODE_RELEASE_PUB=$(realpath "$CAMNODE_RELEASE_PUB"); export CAMNODE_RELEASE_PUB
if [ -n "${CAMNODE_BOOT_SIG:-}" ]; then CAMNODE_BOOT_SIG=$(realpath "$CAMNODE_BOOT_SIG"); export CAMNODE_BOOT_SIG; fi

O=$OUT/br
mkdir -p "$O"
cat "$HERE/external/configs/common.config" "$HERE/external/configs/$BOARD.config" > "$O/camnode_defconfig"
export BR2_DL_DIR=$DL BR2_CCACHE_DIR=$CCACHE
make -C "$OUT/$BR" O="$O" BR2_EXTERNAL="$HERE/external" BR2_DEFCONFIG="$O/camnode_defconfig" defconfig
# Every line of the fragments must survive olddefconfig: a symbol Kconfig dropped (a typo, or an
# unmet dependency) would build something other than what the fragment says.
missing=$(grep -hE '^(BR2_[A-Z0-9_]+=|# BR2_[A-Z0-9_]+ is not set)' "$O/camnode_defconfig" | while read -r l; do
	grep -qxF -- "$l" "$O/.config" || echo "$l"
done)
if [ -n "$missing" ]; then
	echo "build.sh: Kconfig did not keep these lines:" >&2
	echo "$missing" >&2
	exit 1
fi
# Buildroot only warns when a download has no hash file at all (BR2_DOWNLOAD_FORCE_CHECK_HASHES
# covers a hash file without the entry); here an unchecked download fails the build.
make -C "$OUT/$BR" O="$O" 2>&1 | tee "$O/make.log"
if grep -F 'WARNING: no hash file for' "$O/make.log" >&2; then
	echo "build.sh: those downloads were not checked against a hash" >&2
	exit 1
fi

# The same for the kernel: Buildroot applies packages' kernel fixups after the fragments (systemd's
# turns IPv6 on; camnode-init's turns it off again), so check the kernel that was built.
kconf=$(ls -d "$O"/build/linux-*/.config | grep -v '/linux-headers-')
[ "$(echo "$kconf" | wc -l)" = 1 ] || { echo "build.sh: expected one kernel build, found: $kconf" >&2; exit 1; }
missing=$(grep -hE '^(CONFIG_[A-Z0-9_]+=|# CONFIG_[A-Z0-9_]+ is not set)' "$HERE/external/board/common/linux.fragment" \
	"$HERE/external/board/$BOARD/linux.fragment" | while read -r l; do
	grep -qxF -- "$l" "$kconf" || echo "$l"
done)
if [ -n "$missing" ]; then
	echo "build.sh: the kernel did not keep these lines:" >&2
	echo "$missing" >&2
	exit 1
fi

for f in disk.img slot.img slot.json boot.img; do
	cp "$O/images/camnode-$BOARD.$f" "$OUT/"
done
(cd "$OUT" && sha256sum camnode-$BOARD.disk.img camnode-$BOARD.slot.img camnode-$BOARD.boot.img \
	camnode-$BOARD.slot.json > SHA256SUMS)
cat "$OUT/SHA256SUMS"
