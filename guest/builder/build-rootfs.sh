#!/bin/sh
# Builds the root file system of Loop 1's builder machines (W3-builder-image,
# security C-3c-3): the brief client, a static binary whose toolchain is the
# skill format's own validator, and nothing else. No shell, no runtime, no
# agent tools, nothing downloaded: it is built from this repository alone.
#
# Usage: build-rootfs.sh OUT_DIR
# Needs: go. Register OUT_DIR with agentosd's -image builder=OUT_DIR, and
# install guest/builder/launch.json at /usr/lib/agentos/builder/launch.json
# (root-owned, 0644): agentosd's -builder-image and -builder-launch default
# to those.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
# A fresh directory only: the image is exactly what this script writes.
if [ -e "$1" ] && [ -n "$(ls -A "$1")" ]; then
	echo "build-rootfs.sh: $1 is not empty" >&2
	exit 1
fi
out=$(mkdir -p "$1" && cd "$1" && pwd)

cd "$out"
mkdir -p usr/local/bin etc tmp proc dev sys run/agentos
(cd "$repo/broker" && CGO_ENABLED=0 go build -trimpath -ldflags=-buildid= -o "$out/usr/local/bin/agentos-builder" ./cmd/agentos-builder)
printf 'root:x:0:0:root:/:/usr/local/bin/agentos-builder\n' >etc/passwd
printf 'root:x:0:\n' >etc/group
printf '127.0.0.1 localhost\n::1 localhost\n' >etc/hosts
: >etc/resolv.conf # no resolver: the machine has no network but its socket
echo "rootfs ready: $out ($(du -sh "$out" | cut -f1))"
