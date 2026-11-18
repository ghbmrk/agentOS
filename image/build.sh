#!/bin/sh
# Stage the AgentOS device image's tree (PLAN P2-1). Run as root on Linux with network access to
# snapshot.debian.org, storage.googleapis.com (gVisor), nodejs.org and
# registry.npmjs.org (OpenClaw guest), ffmpeg.org or archive.ubuntu.com (libavcodec), github.com
# (llama.cpp) and huggingface.co (the embedding model), and the Go module proxy. CI does this in
# .github/workflows/image.yml's stage job.
# Needs Go, cc with a static libc, make, pkg-config, mtools, erofs-utils, dosfstools, cryptsetup-bin,
# debian-archive-keyring, mmdebstrap.
#
# Usage: build.sh [OUT [VERSION [DRIVERS]]]
# Output in OUT: the image tree (stage/, /usr alone), the apt sources (agentos.sources, and as mkosi's
# package manager tree in pkgmngr/), and the guests' and linked package lists (guest/, linked/). This
# script never runs mkosi (IMG-mkosi-run-bound, #4690, D-276): the image is then built by the pinned
# mkosi v24.3 from image.yml's "Build image" line, run from the repository's top, and finished by
# image/finish.sh OUT VERSION; image/README.md gives the local commands.
# DRIVERS (DEVSLOT-image, D-189), optional: a directory of device drivers built in a private
# repository, each <name>/ holding a static `driver` binary and its entry.json (repository, commit,
# declaration, class row, measure). The public release build passes none and ships none.
#
# AGENTOS_SECURITY_SNAPSHOT, optional: the debian-security snapshot timestamp (YYYYMMDDTHHMMSSZ) the
# image, its initrd and the guest roots install security packages from; image.yml resolves one per run
# for both its builds (#5021). Unset, the build resolves the latest one itself.
#
# Reproducibility: every input is pinned (Debian snapshots, gVisor and Node by hash, OpenClaw by
# lockfile, Go with -trimpath), file times are clamped to the commit time, and partition and
# file-system IDs come from mkosi.conf's Seed, so two builds of one commit give the same /usr
# root hash. VERSION defaults to the commit time, so releases sort in commit order.
set -eu
# A go.work in the repo would override broker/go.mod, go.sum and vendor/ (#4007 Security).
export GOWORK=off
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
# The Debian archive keyring mkosi and guest-base.sh verify the snapshot with: exactly the pinned keys (#5578).
sh "$HERE/debian-archive-keyring.sh"
OUT=$(realpath -m "${1:-$HERE/out}"); DRIVERS=${3:+$(realpath "$3")}
SOURCE_DATE_EPOCH=$(git -c safe.directory="$REPO" -C "$REPO" log -1 --format=%ct); export SOURCE_DATE_EPOCH
VERSION=${2:-$(TZ=UTC git -c safe.directory="$REPO" -C "$REPO" log -1 --date=format-local:%Y%m%d.%H%M%S --format=%cd)}
GVISOR=release-20260928.0
GVISOR_SHA512=c8d3a9fd4d4c4f5b8ff213caa4517356be128d18659ec4cde37828fe797f61a9725a602a846c81a8ed19c057a996515d31c081eba343ed4613a89951ba32ed59

mkdir -p "$OUT"
# One debian-security snapshot for the whole build (IMG-repro-security-pin, #5021): the apt sources
# with their security stanza on it go to mkosi as a package manager tree (mkosi v24.3 copies a
# command-line tree after mkosi.pkgmngr, so this file replaces the committed one for the image and
# its initrd) and to guest-base.sh, and stay in OUT for the reproduce job to compare.
SECURITY_SNAPSHOT=${AGENTOS_SECURITY_SNAPSHOT-}
[ -n "$SECURITY_SNAPSHOT" ] || SECURITY_SNAPSHOT=$(sh "$HERE/security-snapshot.sh" resolve)
sh "$HERE/security-snapshot.sh" sources "$SECURITY_SNAPSHOT" >"$OUT/agentos.sources"
rm -rf "$OUT/pkgmngr"
install -D -m 0644 "$OUT/agentos.sources" "$OUT/pkgmngr/etc/apt/sources.list.d/mkosi.sources"
echo "debian-security snapshot $SECURITY_SNAPSHOT"
STAGE=$OUT/stage; rm -rf "$STAGE"; mkdir -p "$STAGE/usr/lib/agentos/images"

# The broker, the vault process, the owner page, the modem bridge, the keeper: enrollment, the
# unlock step and the kernel (STO-2c) and the mail clerk (MAIL-unit), and the host-disk helper the udev rules below run (HOST-1a),
# static and path-free. No access point or Wi-Fi join (D-178). The device-driver host (DEVSLOT b2b). The
# core's end of the edge link (EDGE-link-core c2c). The camera clerk (CAM-clerk-image) and its decoder
# sessions' process (CAM-decoder-uid). The HomeKit clerk (DEV-homekit-b2c). The shutdown step that
# clears the memory-overwrite request (HW-8, #4794). The owner page's root step (agentos-port1, #5678).
for cmd in agentosd agentos-egress agentos-localui agentos-port1 agentos-modem \
	agentos-enroll agentos-unlock agentos-kernel agentos-clerk-mail agentos-hostdisk agentos-devices agentos-link \
	agentos-camera agentos-camdecode-host agentos-homekit agentos-mor; do
	(cd "$REPO/broker" && CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= \
		-o "$STAGE/usr/lib/agentos/$cmd" "./cmd/$cmd")
done
# The mail clerk's IMAP connection process (#3015), which the clerk's package keeps beside it.
(cd "$REPO/broker" && CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= \
	-o "$STAGE/usr/lib/agentos/agentos-imapconn" ./clerk/inbox/imapconn/cmd/imapconn)
# The requalification case driver (UPD-5r-b2): the host boots it under gVisor from a release's own
# /usr, read-only, so each release ships the driver that runs its cases (broker/vm/requal/driver).
(cd "$REPO/broker" && CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= \
	-o "$STAGE/usr/lib/agentos/agentos-requal-driver" ./vm/requal/driver/cmd/agentos-requal-driver)

# gVisor, the same release and hash as CI's machine tests, with its sidecars beside runsc as CI
# installs them: this release's runsc refuses to start a sandbox without gvisor-bin/ (#1701).
curl -fsSLo "$OUT/gvisor.tar.bz2" \
	"https://storage.googleapis.com/gvisor/releases/release/${GVISOR#release-}/x86_64/gvisor.tar.bz2"
echo "$GVISOR_SHA512  $OUT/gvisor.tar.bz2" | sha512sum -c -
mkdir -p "$OUT/gvisor" && tar -xjf "$OUT/gvisor.tar.bz2" -C "$OUT/gvisor"
install -m 0755 "$OUT/gvisor/runsc" "$STAGE/usr/lib/agentos/runsc"
mkdir -p "$STAGE/usr/lib/agentos/gvisor-bin"
install -m 0755 "$OUT"/gvisor/gvisor-bin/* "$STAGE/usr/lib/agentos/gvisor-bin/"
rm -rf "$OUT/gvisor.tar.bz2" "$OUT/gvisor"

# The photo decoder's one-shot root (CH-23, ARC-5): the static agentos-photo and empty mount
# points, nothing else. The broker mounts it read-only (gvisor.OneShot.Root).
PHOTO=$STAGE/usr/lib/agentos/images/photo
mkdir -p "$PHOTO/proc" "$PHOTO/dev" "$PHOTO/sys"
(cd "$REPO/broker" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid=' \
	-o "$PHOTO/agentos-photo" ./cmd/agentos-photo)
chmod 0755 "$PHOTO/agentos-photo"

# The Debian root from the image's own apt sources (#5570) that the guests' shell, tools and libraries
# come from, and whose toolchain compiles the camera decoder (#5582) and the Codex worker's bwrap
# (#5571), never the build host's, so two runners give the same bytes (IMG-2). Its package list goes
# to OUT/guest/ for the reproduce job; the root is deleted once the guests are built.
sh "$HERE/guest-base.sh" "$OUT/guest-base" "$OUT/guest/agentos-guest.manifest" "$OUT/agentos.sources"
export GUEST_BASE="$OUT/guest-base"
# Each guest build records here the Debian packages whose files it copies (image/guest-shipped.sh).
export GUEST_SHIPPED="$OUT/guest-base.shipped"
true >"$GUEST_SHIPPED"
# The camera decoder's stream root (CAM-clerk b2, NET-2): the static agentos-camdecode on the
# pinned libavcodec, built in the base by its own script (image/camdecode.sh), and libavcodec's
# licence text.
sh "$HERE/camdecode.sh" "$STAGE/usr/lib/agentos/images/camdecode" "$STAGE/usr/share/licenses"

# The local inference service, its pinned llama-server and embedding model, and their licence texts
# (INFER-image, D-230), built by its own script (image/infer.sh); agentosd leaves it off (-infer).
# llama-server is linked statically in the base (image/llamaserver.sh, #5885), which records here
# the Debian packages its link read: the main tree's, not the guests'.
export LINKED_SHIPPED="$OUT/linked.shipped"
true >"$LINKED_SHIPPED"
sh "$HERE/infer.sh" "$STAGE" "$OUT/infer"

# The OpenClaw guest's root file system (P1-7), as an agent-machine image.
sh "$REPO/guest/openclaw/build-rootfs.sh" "$STAGE/usr/lib/agentos/images/openclaw"
# The Codex provider worker's (S8-W1, #1721): provagent's codex declaration names this image, and
# agentosd registers it (-image codex=); the CLI is pinned by npm's integrity hash.
sh "$REPO/guest/codex/build-rootfs.sh" "$STAGE/usr/lib/agentos/images/codex"
sh "$HERE/check_codex_pin.sh" "$REPO" "$STAGE/usr/lib/agentos/images/codex"
# The dpkg status of the packages whose files the guests carry, beside their manifest: the image
# vulnerability check scans them as the "image/guest" tree (image/guest-shipped.sh, #5572).
sh "$HERE/guest-shipped.sh" --status "$GUEST_BASE" "$OUT/guest"
# The dpkg status of the packages the main tree's static binaries link (#5885): the image
# vulnerability check scans them as part of the main tree ("image").
GUEST_SHIPPED=$LINKED_SHIPPED sh "$HERE/guest-shipped.sh" --status "$GUEST_BASE" "$OUT/linked"
rm -rf --one-file-system "$GUEST_BASE" "$GUEST_SHIPPED" "$LINKED_SHIPPED"
unset GUEST_BASE GUEST_SHIPPED LINKED_SHIPPED
# How agentosd starts the agent machine (W1): its -agent-launch default.
install -D -m 0644 "$REPO/guest/openclaw/launch.json" "$STAGE/usr/lib/agentos/guest/launch.json"
# Each setup service's unit lives beside its command (localui ASSUMPTIONS L26).
install -D -m 0644 "$REPO/broker/cmd/agentos-localui/agentos-localui.service" "$STAGE/usr/lib/systemd/system/agentos-localui.service"
install -D -m 0644 "$REPO/broker/cmd/agentos-localui/agentos-localui-claim.service" "$STAGE/usr/lib/systemd/system/agentos-localui-claim.service"
install -D -m 0644 "$REPO/broker/cmd/agentos-modem/agentos-modem.service" "$STAGE/usr/lib/systemd/system/agentos-modem.service"
install -D -m 0644 "$REPO/broker/cmd/agentos-devices/agentos-devices.service" "$STAGE/usr/lib/systemd/system/agentos-devices.service"
# The rule that gives qualified modems' nodes to the bridge's user.
install -D -m 0644 "$REPO/broker/modem/at/udev/71-agentos-modem.rules" "$STAGE/usr/lib/udev/rules.d/71-agentos-modem.rules"
# The host PC's disks stay hidden, unassembled and root-only (HW-8, HOST-1a; hostdisk ASSUMPTIONS
# H8, H11): in the main system only, never the initrd.
for r in 59-agentos-host-disks 64-agentos-host-disks-assembly 72-agentos-host-disks-late; do
	install -D -m 0644 "$REPO/broker/hostdisk/udev/$r.rules" "$STAGE/usr/lib/udev/rules.d/$r.rules"
done
# Device drivers (DEVSLOT-image): each declaration passes devslot.Check (image/drivercheck, one file
# built in the broker's module for this step and never shipped), each binary is static, and each gets the units and user that
# mkosi.finalize's template renders for its name; drivers.json lists them, and mkosi.finalize
# refuses a tree that differs from it.
(cd "$REPO/broker" && CGO_ENABLED=0 go build -trimpath -o "$OUT/drivercheck" ../image/drivercheck/main.go)
python3 "$HERE/finish_image.py" --stage-drivers "$DRIVERS" "$STAGE" "$OUT/drivercheck"
rm -f "$OUT/drivercheck"
chmod -R u+w,go-w "$STAGE"

# The tree is staged. The pinned mkosi runs on the committed config next, out of this script's reach
# (IMG-mkosi-run-bound, #4690, D-276): image.yml's build job runs it, on a runner that never runs this
# script, from the one line in its "Build image" step, and image/finish.sh finishes the image.
echo "staged $STAGE (version $VERSION)"
