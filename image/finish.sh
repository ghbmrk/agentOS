#!/bin/sh
# Finish the image the pinned mkosi built in OUT from the tree image/build.sh staged (IMG-mkosi-run-bound,
# #4690, D-276): the release (agentos_VERSION.usr.raw, .usr-verity.raw, the boot entry, .release.json)
# from the whole drive agentos_VERSION.raw, the initrds for the reproduce job, and SHA256SUMS. Runs as
# root after mkosi, in image.yml's build job, so nothing here can change what mkosi read.
#
# Usage: finish.sh OUT VERSION
set -eu
[ $# -eq 2 ] || { echo "usage: finish.sh OUT VERSION" >&2; exit 2; }
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(realpath "$1"); VERSION=$2; STAGE=$OUT/stage
rm -rf "$OUT/pkgmngr"
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
