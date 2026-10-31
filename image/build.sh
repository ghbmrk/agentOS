#!/bin/sh
# Build the AgentOS device image (PLAN P2-1). Run as root on Linux with network access to
# snapshot.debian.org, security.debian.org, storage.googleapis.com (gVisor), nodejs.org and
# registry.npmjs.org (OpenClaw guest), ffmpeg.org or archive.ubuntu.com (libavcodec), github.com
# (llama.cpp) and huggingface.co (the embedding model), and the Go module proxy. CI does this:
# .github/workflows/image.yml
# Needs mkosi v24.3 (MKOSI=/path/to/mkosi), Go, cc and c++ with a static libc and libstdc++, make,
# cmake, pkg-config, mtools, erofs-utils, dosfstools, cryptsetup-bin, debian-archive-keyring.
#
# Usage: build.sh [OUT [VERSION [DRIVERS]]]
# Output in OUT: agentos_VERSION.raw (the whole drive), the release (agentos_VERSION.usr.raw,
# .usr-verity.raw, the boot entry, .release.json), the package manifest, and SHA256SUMS.
# DRIVERS (DEVSLOT-image, D-189), optional: a directory of device drivers built in a private
# repository, each <name>/ holding a static `driver` binary and its entry.json (repository, commit,
# declaration, class row, measure). The public release build passes none and ships none.
#
# Reproducibility: every input is pinned (Debian snapshot, gVisor and Node by hash, OpenClaw by
# lockfile, Go with -trimpath), file times are clamped to the commit time, and partition and
# file-system IDs come from mkosi.conf's Seed, so two builds of one commit give the same /usr
# root hash. VERSION defaults to the commit time, so releases sort in commit order.
set -eu
# A go.work in the repo would override broker/go.mod, go.sum and vendor/ (#4007 Security).
export GOWORK=off
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
OUT=$(realpath -m "${1:-$HERE/out}"); MKOSI=${MKOSI:-mkosi}; DRIVERS=${3:+$(realpath "$3")}
SOURCE_DATE_EPOCH=$(git -c safe.directory="$REPO" -C "$REPO" log -1 --format=%ct); export SOURCE_DATE_EPOCH
VERSION=${2:-$(TZ=UTC git -c safe.directory="$REPO" -C "$REPO" log -1 --date=format-local:%Y%m%d.%H%M%S --format=%cd)}
GVISOR=release-20260928.0
GVISOR_SHA512=c8d3a9fd4d4c4f5b8ff213caa4517356be128d18659ec4cde37828fe797f61a9725a602a846c81a8ed19c057a996515d31c081eba343ed4613a89951ba32ed59

mkdir -p "$OUT"
STAGE=$OUT/stage; rm -rf "$STAGE"; mkdir -p "$STAGE/usr/lib/agentos/images"

# The broker, the vault process, the owner page, the modem bridge, the keeper: enrollment, the
# unlock step and the kernel (STO-2c) and the mail clerk (MAIL-unit), and the host-disk helper the udev rules below run (HOST-1a),
# static and path-free. No access point or Wi-Fi join (D-178). The device-driver host (DEVSLOT b2b). The
# core's end of the edge link (EDGE-link-core c2c). The camera clerk (CAM-clerk-image). The HomeKit clerk
# (DEV-homekit-b2c).
for cmd in agentosd agentos-egress agentos-localui agentos-modem \
	agentos-enroll agentos-unlock agentos-kernel agentos-clerk-mail agentos-hostdisk agentos-devices agentos-link \
	agentos-camera agentos-homekit; do
	(cd "$REPO/broker" && CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= \
		-o "$STAGE/usr/lib/agentos/$cmd" "./cmd/$cmd")
done
# The mail clerk's IMAP connection process (#3015), which the clerk's package keeps beside it.
(cd "$REPO/broker" && CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= \
	-o "$STAGE/usr/lib/agentos/agentos-imapconn" ./clerk/inbox/imapconn/cmd/imapconn)

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

# The camera decoder's stream root (CAM-clerk b2, NET-2): the static agentos-camdecode on the
# pinned libavcodec, built by its own script (image/camdecode.sh), and libavcodec's licence text.
sh "$HERE/camdecode.sh" "$STAGE/usr/lib/agentos/images/camdecode" "$STAGE/usr/share/licenses" "$OUT/libavcodec"

# The local inference service, its pinned llama-server and embedding model, and their licence texts
# (INFER-image, D-230), built by its own script (image/infer.sh); agentosd leaves it off (-infer).
sh "$HERE/infer.sh" "$STAGE" "$OUT/infer"

# The OpenClaw guest's root file system (P1-7), as an agent-machine image.
sh "$REPO/guest/openclaw/build-rootfs.sh" "$STAGE/usr/lib/agentos/images/openclaw"
# The Codex provider worker's (S8-W1, #1721): provagent's codex declaration names this image, and
# agentosd registers it (-image codex=); the CLI is pinned by npm's integrity hash.
sh "$REPO/guest/codex/build-rootfs.sh" "$STAGE/usr/lib/agentos/images/codex"
sh "$HERE/check_codex_pin.sh" "$REPO" "$STAGE/usr/lib/agentos/images/codex"
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

$MKOSI -C "$HERE/mkosi" -f --image-version="$VERSION" --extra-tree="$STAGE:/" --output-dir "$OUT" build
python3 "$HERE/finish_image.py" "$OUT" "$VERSION" "$STAGE/usr/lib/agentos/drivers.json"
rm -rf "$STAGE"
# The initrds the release's entry boots, copied out of the ESP to OUT/initrd/ under their ESP paths:
# image.yml's reproduce job compares two runners' copies member by member (IMG-2).
rm -rf "$OUT/initrd"
python3 -I -c 'import json, pathlib, subprocess, sys
sys.path.insert(0, sys.argv[1]); import finish_image
out, version = pathlib.Path(sys.argv[2]), sys.argv[3]
img = out / ("agentos_%s.raw" % version)
fs = "%s@@%d" % (img, finish_image.esp_offset(str(img)))
for p in json.loads((out / ("agentos_%s.release.json" % version)).read_text())["boot"]:
    if p.endswith("initrd"):
        dst = out / "initrd" / p
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(subprocess.check_output(["mtype", "-i", fs, "::/" + p]))' "$HERE" "$OUT" "$VERSION"
( cd "$OUT" && sha256sum "agentos_$VERSION.raw" "agentos_$VERSION.usr.raw" "agentos_$VERSION.usr-verity.raw" \
	"agentos_$VERSION+3.conf" "agentos_$VERSION.release.json" > SHA256SUMS && cat SHA256SUMS )
