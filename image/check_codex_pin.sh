#!/bin/sh
# check_codex_pin.sh <guest/codex/build-rootfs.sh> <staged codex tree>
# The box's Codex image must carry usr/lib/agentos/cli-version equal to the CODEX_VERSION its build
# script pins: agentosd's pin gate (#1877, #1895) refuses every provider run otherwise, and the only
# cause it gives is one journal line. build.sh runs this on the staged tree, which becomes the box's
# dm-verity /usr, so the booted image carries exactly what passed (image/ASSUMPTIONS.md I25).
set -eu
script=$1 tree=$2
want=$(sed -n 's/^CODEX_VERSION=\([0-9][0-9.]*\)$/\1/p' "$script")
[ -n "$want" ] || { echo "check_codex_pin: $script pins no CODEX_VERSION" >&2; exit 1; }
# Until #1895 the script writes no cli-version, so there is nothing to hold the tree to yet.
if ! grep -q 'usr/lib/agentos/cli-version' "$script"; then
	echo "check_codex_pin: $script writes no cli-version yet (#1895); not checked" >&2
	exit 0
fi
pin=$tree/usr/lib/agentos/cli-version
# agentosd reads only a regular file (os.OpenRoot), so a link or anything else reads as unpinned.
if [ -L "$pin" ] || [ ! -f "$pin" ]; then
	echo "check_codex_pin: $pin is not a regular file; the box's Codex image would be unpinned" >&2
	exit 1
fi
got=$(cat "$pin"; printf x); got=${got%x}
[ "$got" = "$want" ] || { echo "check_codex_pin: $pin reads [$got], build-rootfs.sh pins [$want]" >&2; exit 1; }
