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

# The broker, the vault process, the Wi-Fi page, the access point loader,
# the modem bridge and the home Wi-Fi helper, static and path-free.
for cmd in agentosd agentos-egress agentos-localui agentos-ap agentos-modem agentos-netjoin; do
	(cd "$REPO/broker" && CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= \
		-o "$STAGE/usr/lib/agentos/$cmd" "./cmd/$cmd")
done

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
install -D -m 0644 "$REPO/broker/cmd/agentos-ap/agentos-ap.service" "$STAGE/usr/lib/systemd/system/agentos-ap.service"
install -D -m 0644 "$REPO/broker/cmd/agentos-modem/agentos-modem.service" "$STAGE/usr/lib/systemd/system/agentos-modem.service"
install -D -m 0644 "$REPO/broker/cmd/agentos-netjoin/agentos-netjoin.service" "$STAGE/usr/lib/systemd/system/agentos-netjoin.service"
# The home Wi-Fi helper's NetworkManager grant, and the rule that gives
# qualified modems' nodes to the bridge's user.
install -D -m 0644 "$REPO/broker/cmd/agentos-netjoin/50-agentos-netjoin.rules" "$STAGE/usr/share/polkit-1/rules.d/50-agentos-netjoin.rules"
# Its system bus policy: NetworkManager sees only the helper's own calls.
install -D -m 0644 "$REPO/broker/cmd/agentos-netjoin/agentos-netjoin.conf" "$STAGE/usr/share/dbus-1/system.d/agentos-netjoin.conf"
install -D -m 0644 "$REPO/broker/modem/at/udev/71-agentos-modem.rules" "$STAGE/usr/lib/udev/rules.d/71-agentos-modem.rules"
chmod -R u+w,go-w "$STAGE"

$MKOSI -C "$HERE/mkosi" -f --image-version="$VERSION" --extra-tree="$STAGE:/" --output-dir "$OUT" build
python3 "$HERE/finish_image.py" "$OUT" "$VERSION"
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
