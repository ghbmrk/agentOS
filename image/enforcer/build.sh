#!/bin/sh
# Build the enforcer's image (ENF-m, NET-2 Hardening; D-229). Run as root on Linux with network
# access to snapshot.debian.org and security.debian.org. CI does this: .github/workflows/enforcer-image.yml
# Needs mkosi v24.3 (MKOSI=/path/to/mkosi), mtools, erofs-utils, dosfstools, cryptsetup-bin,
# debian-archive-keyring, python3.
#
# Usage: ENFORCER_RELEASE_ROOT=root.json AGENTOS_RELEASE_KEYS="k1 k2 ..." build.sh [OUT [VERSION]]
# ENFORCER_RELEASE_ROOT is the enforcer feed's signed TUF root.json (agentos-release init, sign,
# publish, run against the enforcer's own keys); the image ships it as the only root its updates
# are checked against. AGENTOS_RELEASE_KEYS names every agentOS release key (PEM public keys or
# agentOS root.json files); finish_image.py refuses the image if the root or any byte of the disk
# holds one (NET-2 Channel). Both are required: an image without them is not an enforcer release.
# Output in OUT: enforcer_VERSION.raw (the drive), the release (enforcer_VERSION.usr.raw,
# .usr-verity.raw, the boot entry, .release.json, .usr.list), and SHA256SUMS.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../.." && pwd)
OUT=$(realpath -m "${1:-$HERE/out}"); MKOSI=${MKOSI:-mkosi}
: "${ENFORCER_RELEASE_ROOT:?the enforcer feed root.json (ENFORCER_RELEASE_ROOT) is required}"
: "${AGENTOS_RELEASE_KEYS:?the agentOS release keys to refuse (AGENTOS_RELEASE_KEYS) are required}"
SOURCE_DATE_EPOCH=$(git -c safe.directory="$REPO" -C "$REPO" log -1 --format=%ct); export SOURCE_DATE_EPOCH
VERSION=${2:-$(TZ=UTC git -c safe.directory="$REPO" -C "$REPO" log -1 --date=format-local:%Y%m%d.%H%M%S --format=%cd)}
KEYS=
for k in $AGENTOS_RELEASE_KEYS; do KEYS="$KEYS --agentos-key $(realpath "$k")"; done
ROOT=$(realpath "$ENFORCER_RELEASE_ROOT")

mkdir -p "$OUT"
# Refuse a root that holds an agentOS key before spending a build on it.
# shellcheck disable=SC2086 # $KEYS is a list of arguments without spaces.
python3 "$HERE/finish_image.py" --check-root --root "$ROOT" $KEYS
STAGE=$OUT/stage; rm -rf "$STAGE"
install -D -m 0644 "$ROOT" "$STAGE/usr/share/agentos-enforcer/release-root.json"
chmod -R u+w,go-w "$STAGE"

$MKOSI -C "$HERE/mkosi" -f --image-version="$VERSION" --extra-tree="$STAGE:/" --output-dir "$OUT" build
rm -rf "$STAGE"
# shellcheck disable=SC2086
python3 "$HERE/finish_image.py" "$OUT" "$VERSION" --root "$ROOT" $KEYS
( cd "$OUT" && sha256sum "enforcer_$VERSION.raw" "enforcer_$VERSION.usr.raw" "enforcer_$VERSION.usr-verity.raw" \
	"enforcer_$VERSION+3.conf" "enforcer_$VERSION.release.json" > SHA256SUMS && cat SHA256SUMS )
