#!/bin/bash
# Build the device image locally with image.yml's own split (#6161, #6348): image.yml runs build.sh as
# root on one runner ("stage") and the pinned mkosi on another that never runs build.sh ("build"), with
# the stage passed between them as a tar the build side holds to stage/usr, agentos.sources, guest/ and
# linked/. This script runs the same two halves, one per host, so a local image and a CI image are one
# class: each block below is a step of image.yml copied line for line, and tests/test_image.py holds every
# such line equal to the workflow's (MkosiRunBoundTest). CI never runs this script.
#
# Usage: image/local-build.sh stage DIR
#          on the stage host (a disposable VM will do; never one that built): marks the host as one that
#          staged, runs build.sh as root, packs the stage as DIR/stage-COMMIT.tar and prints its SHA-256
#        image/local-build.sh build TAR SHA256 DIR [VERSION]
#          on a host that never staged (marked from then on as one that built), with the pinned mkosi in
#          /opt/mkosi: the commit and the tar are copied into a root-only directory under /var/lib, and the
#          rest runs as root from there (the tar held to the SHA-256 the stage printed, mkosi, finish.sh), so
#          no non-root process reaches a file it reads (#6417); the image then moves to DIR/out
#   Both run from a checkout of one commit with no changed, untracked or ignored file (a tar from another
#   commit is refused), as a user who can sudo, on Linux with build.sh's or mkosi's tools and network. DIR
#   must not exist; a relative DIR or TAR is read from the caller's directory. VERSION defaults to the
#   commit time, as in CI. AGENTOS_SECURITY_SNAPSHOT, if set, is the run's snapshot (and fallback) for both
#   halves, as image.yml's security-snapshot job passes it; unset, build.sh resolves its own and the build
#   half resolves the set its pick must be in. The half's log (DIR/stage.log, or the build's in its root-only
#   directory) is named on exit, pass or fail.
set -euo pipefail
MKOSI_COMMIT=26673f65e17ae099bb0cf65928fe70c93b8a6a37  # v24.3, as image.yml's "Install build and boot tools" checks out
# Each half writes its own mark, then refuses a host holding the other's (#6380, #6417): one host never plays
# both halves, even two run at once (each writes before it checks).
STAGE_MARK=/var/lib/agentos-stage-host BUILD_MARK=/var/lib/agentos-build-host
# Refuse a host holding mark $1 ($2 names the role it marks). Read as root, the answer is present or absent;
# a sudo that fails prints neither, and that stops the run rather than reading as "no mark" (#6417).
refuse_mark() {
	local s; s=$(sudo sh -c 'if [ -e "$1" ] || [ -L "$1" ]; then echo present; else echo absent; fi' sh "$1") || s=
	case $s in
		absent) ;;
		present) echo "local-build.sh: this host $2 ($1), so it cannot $MODE; $MODE on a host that never $2" >&2; exit 1 ;;
		*) echo "local-build.sh: cannot read $1 as root (sudo failed), so this host's past role is unknown; stopping" >&2; exit 1 ;;
	esac
}
usage() { echo "usage: image/local-build.sh stage DIR | build TAR SHA256 DIR [VERSION]" >&2; exit 2; }
case "${1-} $#" in "stage 2"|"build 4"|"build 5"|"build-root 4") ;; *) usage ;; esac
MODE=$1
if [ "$MODE" = build-root ]; then
	[ "$(id -u)" = 0 ] || { echo "local-build.sh: build-root is the build's second part, run as root by build; run build" >&2; exit 2; }
	# The build's second part, run below by the first as root from the root-only copy W of the commit: W holds
	# src/ (the commit), stage-in/stage.tar (the tar) and every file the steps write (#6417).
	RUNNER_TEMP=$2 SHA256=$3 VERSION=$4
	cd "$RUNNER_TEMP/src"  # the first part names the log on exit
	case ${SOURCE_DATE_EPOCH-} in ""|*[!0-9]*) echo "local-build.sh: SOURCE_DATE_EPOCH '${SOURCE_DATE_EPOCH-}' is not a count of seconds" >&2; exit 2 ;; esac
fi
if [ "$MODE" = build ]; then
	TAR=$(realpath -e -- "$2"); SHA256=$3; shift 2
fi
case "$MODE" in build|build-root) case "$SHA256" in *[!0-9a-f]*|"") usage ;; esac; [ ${#SHA256} = 64 ] || usage ;; esac
[ "$MODE" = build-root ] || { RUNNER_TEMP=$(realpath -m -- "$2"); VERSION=${3-}; }  # before the cd: relative paths are the caller's (#6348)
case "$VERSION" in
	-*|*[!0-9A-Za-z.+_-]*) echo "local-build.sh: VERSION may hold only 0-9 A-Z a-z . + _ - and may not start with -" >&2; exit 2 ;;
esac
AGENTOS_SECURITY_SNAPSHOT=${AGENTOS_SECURITY_SNAPSHOT-}
if [ "$MODE" != build-root ]; then
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/.." && pwd)
cd "$REPO"  # image.yml's steps run from the repository's top
# Ignored files too (#6380): mkosi reads an ignored image/mkosi/mkosi.local.conf, and go build an ignored .go file.
[ -z "$(git status --porcelain --ignored --untracked-files=all)" ] || { echo "local-build.sh: the checkout has changes, untracked or ignored files (git status --ignored); CI builds only a commit, so commit them (or move them out, git clean -ndx lists the rest) first" >&2; exit 1; }
COMMIT=$(git rev-parse HEAD)
if [ "$MODE" = build ]; then
	[ "$(basename "$TAR")" = "stage-$COMMIT.tar" ] || { echo "local-build.sh: $TAR is not the stage of this checkout's commit (stage-$COMMIT.tar)" >&2; exit 1; }
	{ [ "$(sudo git -C /opt/mkosi rev-parse HEAD)" = "$MKOSI_COMMIT" ] && [ -z "$(sudo git -C /opt/mkosi status --porcelain --ignored --untracked-files=all)" ]; } || {
		echo "local-build.sh: /opt/mkosi is not an unchanged mkosi v24.3 at $MKOSI_COMMIT; install it as image.yml does:" >&2
		echo "  sudo rm -rf /opt/mkosi && sudo git clone -q https://github.com/systemd/mkosi /opt/mkosi && sudo git -C /opt/mkosi -c advice.detachedHead=false checkout -q $MKOSI_COMMIT" >&2
		exit 1; }
	sudo touch "$BUILD_MARK"  # before any byte of a stage is read: from here on this host never stages
	refuse_mark "$STAGE_MARK" staged  # build.sh ran here as root
else
	sudo touch "$STAGE_MARK"  # before build.sh: from here on this host never builds
	refuse_mark "$BUILD_MARK" built  # build.sh as root here could reach what the builds left
fi
mkdir -- "$RUNNER_TEMP"  # a fresh directory, as each runner's
fi

if [ "$MODE" = stage ]; then
	trap 'echo "local-build.sh: stage log $RUNNER_TEMP/stage.log" >&2' EXIT
	# image.yml stage job, "Stage the image tree (image/build.sh)".
	sudo env "PATH=$PATH" "AGENTOS_SECURITY_SNAPSHOT=$AGENTOS_SECURITY_SNAPSHOT" HOME=/root GOCACHE=/tmp/gocache image/build.sh "$RUNNER_TEMP/out" 2>&1 | tee "$RUNNER_TEMP/stage.log"
	# "Pack the stage".
	[ "$(sudo ls -A "$RUNNER_TEMP/out/stage")" = usr ] || { echo "::error::OUT/stage holds more than usr/"; exit 1; }
	sudo tar -C "$RUNNER_TEMP/out" --numeric-owner -cf "$RUNNER_TEMP/stage.tar" stage agentos.sources guest linked
	mv "$RUNNER_TEMP/stage.tar" "$RUNNER_TEMP/stage-$COMMIT.tar"
	SHA256=$(sha256sum < "$RUNNER_TEMP/stage-$COMMIT.tar"); SHA256=${SHA256%% *}
	echo "agentOS stage of $COMMIT in $RUNNER_TEMP/stage-$COMMIT.tar, SHA-256 $SHA256; build it on a host that never staged:"
	echo "  image/local-build.sh build stage-$COMMIT.tar $SHA256 DIR"
	exit 0
fi

if [ "$MODE" = build ]; then
	SOURCE_DATE_EPOCH=$(git log -1 --format=%ct "$COMMIT")
	VERSION=${VERSION:-$(TZ=UTC git log -1 --date=format-local:%Y%m%d.%H%M%S --format=%cd "$COMMIT")}
	# W and every directory above it are root's (mktemp makes W 0700 in /var/lib): no non-root process can
	# rename, replace or write anything the build reads from here on, the commit, the tar or what the steps
	# write, so the tar hashed is the tar unpacked and the tree checked is the tree mkosi reads (#6417).
	W=$(sudo mktemp -d /var/lib/agentos-build.XXXXXXXX)
	# On exit, name the log only where it is: in DIR once the image is out, else in W once mkosi has written it.
	# A failed build keeps W for reading (the log, or the copies a check before mkosi refused) and says how to remove it.
	BUILD_LOG=
	trap 'if [ -n "$BUILD_LOG" ]; then echo "local-build.sh: build log $BUILD_LOG" >&2
	elif sudo test -e "$W/build.log"; then echo "local-build.sh: build log $W/build.log (root-only); once read: sudo rm -rf $W" >&2
	else echo "local-build.sh: the build stopped before mkosi, so it wrote no log; $W (root-only) holds the copied commit and tar; once read: sudo rm -rf $W" >&2; fi' EXIT
	sudo mkdir "$W/src" "$W/stage-in"
	# The commit's objects (not its parents) go into root's own repository W/git, where index-pack checks every
	# object against its id and fsck's rules, and root checks out COMMIT's tree with no config or attributes but its own and the tree's: the
	# caller's git config, .git/info/attributes or hooks reach no byte of W/src (#6417). A pack that lacks an
	# object, or holds another commit, fails the checkout.
	rootgit() { sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git "$@"; }
	g() { rootgit --git-dir="$W/git" --work-tree="$W/src" "$@"; }
	rootgit init -q --bare "$W/git"
	git rev-list --objects -n 1 "$COMMIT" | git pack-objects -q --stdout | g index-pack --fsck-objects --stdin >/dev/null
	g read-tree -u --reset "$COMMIT^{tree}"
	# The index is the commit's tree, every file in W/src matches it, and W/src holds no other file.
	[ "$(g write-tree)" = "$(g rev-parse "$COMMIT^{tree}")" ] && g diff-files --quiet && [ -z "$(g ls-files --others)" ] \
	  || { echo "local-build.sh: the copy of $COMMIT in $W/src is not its tree" >&2; exit 1; }
	sudo install -m 0444 "$TAR" "$W/stage-in/stage.tar"  # its download-artifact step
	# Root's own PATH, not the caller's: a directory of the caller's in it would let a non-root process choose
	# the tar, sed or tool mkosi runs as root.
	sudo env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root "AGENTOS_SECURITY_SNAPSHOT=$AGENTOS_SECURITY_SNAPSHOT" "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" bash "$W/src/image/local-build.sh" build-root "$W" "$SHA256" "$VERSION"
	sudo mv "$W/out" "$RUNNER_TEMP/out"; sudo mv "$W/build.log" "$RUNNER_TEMP/build.log"; BUILD_LOG=$RUNNER_TEMP/build.log
	sudo rm -rf "$W"
	echo "agentOS image $VERSION of $COMMIT in $RUNNER_TEMP/out"
	exit 0
fi

SNAPSHOTS=${AGENTOS_SECURITY_SNAPSHOT:-$(sh image/security-snapshot.sh resolve)}  # image.yml's security-snapshot job
# The copy read below is the tar the stage made, by content (#6380): the name only says which commit.
GOT=$(sha256sum < "$RUNNER_TEMP/stage-in/stage.tar"); GOT=${GOT%% *}
[ "$GOT" = "$SHA256" ] || { echo "local-build.sh: the tar has SHA-256 $GOT, not the $SHA256 its stage printed" >&2; exit 1; }
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
# Unset on a host, each half resolves the snapshot at its own time, so the picks can differ (#6380).
STAGED=$(sed -n 's|^URIs: https://snapshot\.debian\.org/archive/debian-security/\([0-9]\{8\}T[0-9]\{6\}Z\)/$|\1|p' "$RUNNER_TEMP/out/agentos.sources")
case " $SNAPSHOTS " in
  *" $STAGED "*) ;;
  *) [ -z "$STAGED" ] || { echo "local-build.sh: the stage's debian-security snapshot $STAGED is not one of this host's ($SNAPSHOTS); the halves resolved it at different times, so set AGENTOS_SECURITY_SNAPSHOT to one of this host's on both hosts and stage again" >&2; exit 1; } ;;
esac
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
