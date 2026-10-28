#!/usr/bin/env bash
# Build ArduPilot Copter SITL at the pin, with the signed-only patch applied
# (DRONE-sim, #3516, brief decisions 3 and 4). ArduPilot is GPL-3.0: it is
# built and run here, in CI, and never shipped or linked (NOTICE).
#
# Usage: build.sh OUT_DIR
# Writes OUT_DIR/arducopter, OUT_DIR/copter.parm (the autotest defaults at the
# same commit) and OUT_DIR/BUILD (what was built). Fails if the tag does not
# name the pinned commit or the patch does not apply.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?usage: build.sh OUT_DIR}
repo=https://github.com/ArduPilot/ardupilot.git
pin() { awk -v k="$1" '$1 == k { print $2 }' "$here/ardupilot.pin"; }
tag=$(pin tag)
commit=$(pin commit)
patch=$here/$(pin patch)
[[ $commit =~ ^[0-9a-f]{40}$ ]] || { echo "ardupilot.pin: commit is not a full SHA" >&2; exit 1; }
[ -f "$patch" ] || { echo "ardupilot.pin: patch $patch is missing" >&2; exit 1; }
tagged=$(git ls-remote "$repo" "refs/tags/$tag" "refs/tags/$tag^{}" | awk '{ print $1 }' | tail -n 1)
[ "$tagged" = "$commit" ] || { echo "tag $tag is $tagged, the pin says $commit" >&2; exit 1; }

src=$(mktemp -d)
git -C "$src" init -q
git -C "$src" remote add origin "$repo"
git -C "$src" fetch -q --depth 1 origin "$commit"
git -C "$src" checkout -q FETCH_HEAD
[ "$(git -C "$src" rev-parse HEAD)" = "$commit" ] || { echo "checked out the wrong commit" >&2; exit 1; }
git -C "$src" submodule update -q --init --recursive --depth 1
git -C "$src" apply --check "$patch" || { echo "the signed-only patch no longer applies at $commit" >&2; exit 1; }
git -C "$src" apply "$patch"

python3 -m venv "$src/.venv"
"$src/.venv/bin/pip" install -q empy==3.3.4 pexpect==4.9.0 future==1.0.0 setuptools
(
  cd "$src"
  export PATH="$src/.venv/bin:$PATH"
  ./waf configure --board sitl >/dev/null
  ./waf copter
)
mkdir -p "$out"
cp "$src/build/sitl/bin/arducopter" "$out/arducopter"
cp "$src/Tools/autotest/default_params/copter.parm" "$out/copter.parm"
{
  echo "tag $tag"
  echo "commit $commit"
  echo "patch $(sha256sum "$patch" | cut -d' ' -f1)"
} > "$out/BUILD"
rm -rf "$src"
