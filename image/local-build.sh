#!/bin/bash
# Build the device image locally with image.yml's own split (#6161, #6348): image.yml runs build.sh as
# root on one runner ("stage") and the pinned mkosi on another that never runs build.sh ("build"), with
# the stage passed between them as a tar the build side holds to stage/usr, agentos.sources, guest/ and
# linked/. This script runs the same two halves, one per host, so a local image and a CI image are one
# class: each block below is a step of image.yml copied line for line, and tests/test_image.py holds every
# such line equal to the workflow's (MkosiRunBoundTest). CI never runs this script.
#
# Usage: image/local-build.sh stage DIR
#          on the stage host: build.sh as root, then the stage packed as DIR/stage-COMMIT.tar
#        image/local-build.sh build TAR DIR [VERSION]
#          on a host where build.sh never ran as root, with the pinned mkosi in /opt/mkosi: the tar held,
#          then mkosi and finish.sh; the image lands in DIR/out
#   Both run from a clean checkout of one commit (a tar from another commit is refused), as a user who
#   can sudo, on Linux with build.sh's or mkosi's tools and network. DIR must not exist; a relative DIR
#   or TAR is read from the caller's directory. VERSION defaults to the commit time, as in CI.
#   AGENTOS_SECURITY_SNAPSHOT, if set, is the run's snapshot (and fallback) for both halves, as image.yml's
#   security-snapshot job passes it; unset, build.sh resolves its own and the build half resolves the set
#   its pick must be in. The half's log (DIR/stage.log or DIR/build.log) is named on exit, pass or fail.
set -euo pipefail
MKOSI_COMMIT=26673f65e17ae099bb0cf65928fe70c93b8a6a37  # v24.3, as image.yml's "Install build and boot tools" checks out
usage() { echo "usage: image/local-build.sh stage DIR | build TAR DIR [VERSION]" >&2; exit 2; }
case "${1-} $#" in "stage 2"|"build 3"|"build 4") ;; *) usage ;; esac
MODE=$1
if [ "$MODE" = build ]; then TAR=$(realpath -e -- "$2"); shift; fi
RUNNER_TEMP=$(realpath -m -- "$2"); VERSION=${3-}  # before the cd: relative paths are the caller's (#6348)
case "$VERSION" in
	-*|*[!0-9A-Za-z.+_-]*) echo "local-build.sh: VERSION may hold only 0-9 A-Z a-z . + _ - and may not start with -" >&2; exit 2 ;;
esac
AGENTOS_SECURITY_SNAPSHOT=${AGENTOS_SECURITY_SNAPSHOT-}
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
cd "$REPO"  # image.yml's steps run from the repository's top
[ -z "$(git status --porcelain)" ] || { echo "local-build.sh: the checkout has changes or untracked files; CI builds only a commit, so commit them (or move them out) first" >&2; exit 1; }
COMMIT=$(git rev-parse HEAD)
if [ "$MODE" = build ]; then
	[ "$(basename "$TAR")" = "stage-$COMMIT.tar" ] || { echo "local-build.sh: $TAR is not the stage of this checkout's commit (stage-$COMMIT.tar)" >&2; exit 1; }
	{ [ "$(sudo git -C /opt/mkosi rev-parse HEAD)" = "$MKOSI_COMMIT" ] && [ -z "$(sudo git -C /opt/mkosi status --porcelain)" ]; } || {
		echo "local-build.sh: /opt/mkosi is not an unchanged mkosi v24.3 at $MKOSI_COMMIT; install it as image.yml does:" >&2
		echo "  sudo rm -rf /opt/mkosi && sudo git clone -q https://github.com/systemd/mkosi /opt/mkosi && sudo git -C /opt/mkosi -c advice.detachedHead=false checkout -q $MKOSI_COMMIT" >&2
		exit 1; }
fi
mkdir -- "$RUNNER_TEMP"  # a fresh directory, as each runner's
trap 'echo "local-build.sh: $MODE log $RUNNER_TEMP/$MODE.log" >&2' EXIT

if [ "$MODE" = stage ]; then
	# image.yml stage job, "Stage the image tree (image/build.sh)".
	sudo env "PATH=$PATH" "AGENTOS_SECURITY_SNAPSHOT=$AGENTOS_SECURITY_SNAPSHOT" HOME=/root GOCACHE=/tmp/gocache image/build.sh "$RUNNER_TEMP/out" 2>&1 | tee "$RUNNER_TEMP/stage.log"
	# "Pack the stage".
	[ "$(sudo ls -A "$RUNNER_TEMP/out/stage")" = usr ] || { echo "::error::OUT/stage holds more than usr/"; exit 1; }
	sudo tar -C "$RUNNER_TEMP/out" --numeric-owner -cf "$RUNNER_TEMP/stage.tar" stage agentos.sources guest linked
	mv "$RUNNER_TEMP/stage.tar" "$RUNNER_TEMP/stage-$COMMIT.tar"
	echo "agentOS stage of $COMMIT in $RUNNER_TEMP/stage-$COMMIT.tar; build it on another host: image/local-build.sh build TAR DIR"
	exit 0
fi

SNAPSHOTS=${AGENTOS_SECURITY_SNAPSHOT:-$(sh image/security-snapshot.sh resolve)}  # image.yml's security-snapshot job
mkdir "$RUNNER_TEMP/stage-in"; cp "$TAR" "$RUNNER_TEMP/stage-in/stage.tar"  # its download-artifact step
# image.yml build job, "Unpack the stage".
t="$RUNNER_TEMP/stage-in/stage.tar"
tar -tf "$t" > "$RUNNER_TEMP/stage.list"
if grep -Evx 'stage/|stage/usr/|stage/usr/.+|agentos\.sources|guest/|guest/.+|linked/|linked/.+' "$RUNNER_TEMP/stage.list" \
  || grep -E '(^|/)\.\.(/|$)' "$RUNNER_TEMP/stage.list"; then
  echo "::error::the stage tar holds a member outside stage/usr, agentos.sources, guest/ and linked/ (above)"; exit 1
fi
sudo mkdir "$RUNNER_TEMP/out"
sudo tar -C "$RUNNER_TEMP/out" --numeric-owner -xf "$t"
rm -rf "$RUNNER_TEMP/stage-in"
o="$RUNNER_TEMP/out"
{ [ -d "$o/stage" ] && [ ! -h "$o/stage" ] && [ -d "$o/stage/usr" ] && [ ! -h "$o/stage/usr" ] \
  && [ "$(sudo ls -A "$o/stage")" = usr ] && [ -f "$o/agentos.sources" ] && [ ! -h "$o/agentos.sources" ] \
  && [ ! -e "$o/pkgmngr" ]; } || { echo "::error::the stage is not stage/usr alone (directories, no links) and a regular agentos.sources"; exit 1; }
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
VERSION=${VERSION:-$(TZ=UTC git log -1 --date=format-local:%Y%m%d.%H%M%S --format=%cd)}
# "Build image".
OUT=$RUNNER_TEMP/out
AGENTOS_SECURITY_SNAPSHOT=$(sed -n 's|^URIs: https://snapshot\.debian\.org/archive/debian-security/\([0-9]\{8\}T[0-9]\{6\}Z\)/$|\1|p' "$OUT/agentos.sources")
case " $SNAPSHOTS " in
  *" $AGENTOS_SECURITY_SNAPSHOT "*) [ -n "$AGENTOS_SECURITY_SNAPSHOT" ] ;;
  *) echo "::error::the stage's debian-security snapshot '$AGENTOS_SECURITY_SNAPSHOT' is not one of this run's ($SNAPSHOTS)"; exit 1 ;;
esac
sh image/security-snapshot.sh sources "$AGENTOS_SECURITY_SNAPSHOT" > "$RUNNER_TEMP/mkosi.sources"  # refuses an empty or multi-line value
cmp "$RUNNER_TEMP/mkosi.sources" "$OUT/agentos.sources"
sudo rm -rf "$OUT/pkgmngr"
sudo install -D -m 0644 "$RUNNER_TEMP/mkosi.sources" "$OUT/pkgmngr/etc/apt/sources.list.d/mkosi.sources"
sudo env "PATH=$PATH" HOME=/root "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" /opt/mkosi/bin/mkosi -C image/mkosi -f --package-manager-tree="$OUT/pkgmngr" --image-version="$VERSION" --environment=AGENTOS_SECURITY_SNAPSHOT="$AGENTOS_SECURITY_SNAPSHOT" --extra-tree="$OUT/stage/usr:/usr" --output-dir "$OUT" build 2>&1 | tee "$RUNNER_TEMP/build.log"
# "Finish the image (image/finish.sh)".
sudo env "PATH=$PATH" "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" image/finish.sh "$RUNNER_TEMP/out" "$VERSION"
echo "agentOS image $VERSION of $COMMIT in $OUT"
