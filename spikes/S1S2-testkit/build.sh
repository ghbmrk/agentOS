#!/bin/sh
# Build the S1/S2 test kit image. Run as root on Linux with network access to deb.debian.org.
# Needs mkosi v24.3 (MKOSI=/path/to/mkosi), mtools, erofs-utils, dosfstools, debian-archive-keyring.
# Output: OUT/agentos-tk_1.raw and OUT/SHA256SUMS. CI does this for you: .github/workflows/testkit.yml
set -e
HERE=$(cd "$(dirname "$0")" && pwd); OUT=$(realpath -m "${1:-$HERE/out}"); MKOSI=${MKOSI:-mkosi}
# The Debian archive keyring mkosi verifies deb.debian.org with: exactly the pinned keys (#5578, #5933).
sh "$HERE/../../image/debian-archive-keyring.sh"
mkdir -p "$OUT"
$MKOSI -C "$HERE/mkosi" -f --output-dir "$OUT" build
python3 "$HERE/finish_image.py" "$OUT/agentos-tk_1.raw"
( cd "$OUT" && sha256sum agentos-tk_1.raw > SHA256SUMS && cat SHA256SUMS )
