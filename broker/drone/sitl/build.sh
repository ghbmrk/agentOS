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
pin() { awk -v k="$1" '$1 == k { print $2 }' "$here/ardupilot.pin"; }
repo=$(pin repo)
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

# The build's Python tools, each identified by its sha256 (CI-pin-liveness-1, #6588). They live in this
# file, not a requirements file beside it, so drone-sitl.yml's cache key (pin, patch, build.sh) covers
# them. --no-deps: only what is listed is installed, so ptyprocess (pexpect's one dependency) is listed.
# setuptools goes in first and empy, an sdist only, builds against it (--no-build-isolation), so no
# unhashed build backend is fetched.
cat > "$src/build-requirements.txt" <<'REQ'
setuptools==84.2.1 --hash=sha256:ca140b45d5325a9478f880e351484f62fef15f336462e449ca0c03c873d589c2
REQ
cat > "$src/requirements.txt" <<'REQ'
empy==3.3.4 --hash=sha256:73ac49785b601479df4ea18a7c79bc1304a8a7c34c02b9472cf1206ae88f01b3
pexpect==4.9.0 --hash=sha256:7236d1e080e4936be2dc3e326cec0af72acf9212a7e1d060210e70a47e253523
ptyprocess==0.7.0 --hash=sha256:4b41f3967fce3af57cc7e94b888626c18bf37a083e3651ca8feeb66d492fef35
future==1.0.0 --hash=sha256:929292d34f5872e70396626ef385ec22355a1fae8ad29e1a734c3e43f9fbc216
REQ
python3 -m venv "$src/.venv"
(
  cd "$src"
  export PATH="$src/.venv/bin:$PATH"
  [ "$(command -v python3)" = "$src/.venv/bin/python3" ] || { echo "python3 is not the build venv's" >&2; exit 1; }
  python3 -m pip install -q --disable-pip-version-check --require-hashes --no-deps -r build-requirements.txt
  python3 -m pip install -q --disable-pip-version-check --require-hashes --no-deps --no-build-isolation -r requirements.txt
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
