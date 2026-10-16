#!/bin/sh
# check_codex_pin.sh <repo root> <staged codex tree>
# The box's Codex image must carry usr/lib/agentos/cli-version holding the CODEX_VERSION that
# guest/codex/build-rootfs.sh pins: agentosd's pin gate (#1877, #1895) refuses every provider run
# otherwise, and the only cause it gives is one journal line. build.sh runs this on the staged tree,
# which becomes the box's dm-verity /usr, so the booted image carries exactly what passed
# (image/ASSUMPTIONS.md I25).
set -eu
repo=$1 tree=$2
script=$repo/guest/codex/build-rootfs.sh
reader=$repo/broker/cmd/agentosd/imagepin.go
want=$(sed -n 's/^CODEX_VERSION=\([0-9][0-9.]*\)$/\1/p' "$script")
[ -n "$want" ] || { echo "check_codex_pin: $script pins no CODEX_VERSION" >&2; exit 1; }
# Until #1895 agentosd has no pin reader, so nothing reads the file yet. The key is the consumer, not
# build-rootfs.sh's text: once the reader is in the tree, a missing file fails however the script
# writes it (#1897 delta review, finding 2).
if [ ! -e "$reader" ] && ! grep -rqs 'usr/lib/agentos/cli-version' "$repo/broker/cmd/agentosd"; then
	echo "check_codex_pin: agentosd reads no cli-version yet (#1895); not checked" >&2
	exit 0
fi
pin=$tree/usr/lib/agentos/cli-version
# agentosd reads only a regular file (os.OpenRoot), so a link or anything else reads as unpinned.
if [ -L "$pin" ] || [ ! -f "$pin" ]; then
	echo "check_codex_pin: $pin is not a regular file; the box's Codex image would be unpinned" >&2
	exit 1
fi
# agentosd's rule (imagepin.go readCLIPin): the version, then at most one trailing newline.
got=$(cat "$pin"; printf x); got=${got%x}
nl='
'
[ "$got" = "$want" ] || [ "$got" = "$want$nl" ] ||
	{ echo "check_codex_pin: $pin reads [$got], build-rootfs.sh pins [$want]" >&2; exit 1; }
