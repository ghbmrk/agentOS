#!/bin/sh
# Builds the root file system of Loop 1's builder machines (W3-builder-image,
# security C-3c-3): the brief client, a static binary whose toolchain is the
# skill format's own validator, and nothing else. No shell, no runtime, no
# agent tools, nothing downloaded: it is built from this repository alone.
#
# Usage: build-rootfs.sh OUT_DIR
# Needs: go. Register OUT_DIR with agentosd's -image builder=OUT_DIR and
# name it with -builder-image builder (-builder-launch guest/builder/launch.json).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=$(mkdir -p "$1" && cd "$1" && pwd)

cd "$out"
mkdir -p usr/local/bin etc tmp proc dev sys run/agentos
(cd "$repo/broker" && CGO_ENABLED=0 go build -trimpath -o "$out/usr/local/bin/agentos-builder" ./cmd/agentos-builder)
printf 'root:x:0:0:root:/:/usr/local/bin/agentos-builder\n' >etc/passwd
printf 'root:x:0:\n' >etc/group
printf '127.0.0.1 localhost\n::1 localhost\n' >etc/hosts
: >etc/resolv.conf # no resolver: the machine has no network but its socket
echo "rootfs ready: $out ($(du -sh "$out" | cut -f1))"
