#!/bin/bash
# Build the device image locally in one command (IMG-mkosi-run-bound-fu-local, #6161): the three steps
# image/README.md explains, with the four values the mkosi step needs derived here. Local only: CI never
# runs this; image.yml runs the same three steps itself, build.sh in its stage job and the mkosi line and
# finish.sh in its build job, so nothing here is on the release path. The mkosi line below is
# byte-identical to image.yml's "Build image" line (tests/test_image.py pins both to one string).
#
# Usage: image/local-build.sh OUT [VERSION]
#   Run as a user who can sudo, on a Linux host with build.sh's tools and network, and with the pinned
#   mkosi v24.3 in /opt/mkosi (image.yml's "Install build and boot tools" step).
#   VERSION defaults to the commit time, as build.sh's does. AGENTOS_SECURITY_SNAPSHOT, if set, goes to
#   build.sh as in CI; unset, build.sh resolves one. The mkosi log is written to a fresh temporary
#   directory, named at the end.
set -euo pipefail
[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: image/local-build.sh OUT [VERSION]" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
cd "$REPO"  # mkosi's -C image/mkosi is relative to the repository's top, as in image.yml
OUT=$(realpath -m "$1")
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
VERSION=${2:-$(TZ=UTC git log -1 --date=format-local:%Y%m%d.%H%M%S --format=%cd)}
RUNNER_TEMP=$(mktemp -d)

# 1. Stage the tree (as image.yml's stage job runs it).
sudo env "PATH=$PATH" ${AGENTOS_SECURITY_SNAPSHOT:+"AGENTOS_SECURITY_SNAPSHOT=$AGENTOS_SECURITY_SNAPSHOT"} HOME=/root \
	image/build.sh "$OUT" "$VERSION"

# 2. The snapshot the stage picked, read from OUT/agentos.sources as image.yml's build job reads it, and
# checked to be exactly the sources security-snapshot.sh writes for it.
AGENTOS_SECURITY_SNAPSHOT=$(sed -n 's|^URIs: https://snapshot\.debian\.org/archive/debian-security/\([0-9]\{8\}T[0-9]\{6\}Z\)/$|\1|p' "$OUT/agentos.sources")
sh image/security-snapshot.sh sources "$AGENTOS_SECURITY_SNAPSHOT" > "$RUNNER_TEMP/mkosi.sources"  # refuses an empty or multi-line value
cmp "$RUNNER_TEMP/mkosi.sources" "$OUT/agentos.sources"
sudo env "PATH=$PATH" HOME=/root "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" /opt/mkosi/bin/mkosi -C image/mkosi -f --package-manager-tree="$OUT/pkgmngr" --image-version="$VERSION" --environment=AGENTOS_SECURITY_SNAPSHOT="$AGENTOS_SECURITY_SNAPSHOT" --extra-tree="$OUT/stage/usr:/usr" --output-dir "$OUT" build 2>&1 | tee "$RUNNER_TEMP/build.log"

# 3. Finish the release (as image.yml's build job runs it).
sudo env "PATH=$PATH" "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" image/finish.sh "$OUT" "$VERSION"
echo "agentOS image $VERSION in $OUT; mkosi log $RUNNER_TEMP/build.log"
