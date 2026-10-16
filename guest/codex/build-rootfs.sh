#!/bin/sh
# Builds the root file system of the Codex provider worker (S8-W1, #807; CRED-5 broker-held):
# the pinned official Codex CLI, its managed config and requirements, the launch spec, and the
# shell and tools its tool subprocesses need. It holds no login: no auth.json is written here
# (#1015 writes the placeholder into CODEX_HOME at machine create).
#
# Usage: build-rootfs.sh OUT_DIR
# Needs: Go (unless FORWARDER_BIN is set), curl (unless CODEX_TARBALL is set), openssl, tar, sha256sum, and the host's /bin/sh,
# /bin/bash and coreutils, which are copied in with their libraries.
# CODEX_TARBALL=<file> uses a local copy of the pinned tarball instead of downloading it; it is
# still checked against the pinned hash.
# Hook for #809 (the runsc measurement of guest/codex/ASSUMPTIONS.md C1-C15): register OUT_DIR as
# an image with agentosd (-image codex=OUT_DIR) and run the measurements in a machine from it.
# Nothing here is measured under runsc.
set -eu
CODEX_VERSION=0.162.1
CODEX_PKG=codex-$CODEX_VERSION-linux-x64
CODEX_URL=https://registry.npmjs.org/@openai/codex/-/$CODEX_PKG.tgz
# npm's published integrity for the tarball (registry.npmjs.org/@openai/codex/0.162.1-linux-x64).
CODEX_INTEGRITY=sha512-cjK2mdHIfEepZ1lQ1MX3aTQC+8ncIsvnacl/6vI2dIIcfP8/MrhTQ2+qRlkXFNDzJSj1d36quIszP+3/4CUJWQ==
VENDOR=package/vendor/x86_64-unknown-linux-musl

here=$(cd "$(dirname "$0")" && pwd)
# A fresh directory only: the image is exactly what this script writes.
if [ -e "$1" ] && [ -n "$(ls -A "$1")" ]; then
	echo "build-rootfs.sh: $1 is not empty" >&2
	exit 1
fi
out=$(mkdir -p "$1" && cd "$1" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ -n "${CODEX_TARBALL:-}" ]; then
	cp "$CODEX_TARBALL" "$work/codex.tgz"
else
	curl -fsSLo "$work/codex.tgz" "$CODEX_URL"
fi
got=sha512-$(openssl dgst -sha512 -binary "$work/codex.tgz" | openssl base64 -A)
[ "$got" = "$CODEX_INTEGRITY" ] || { echo "codex tarball integrity $got" >&2; exit 1; }

cd "$out"
mkdir -p usr/local/bin usr/bin bin lib64 etc/codex opt/codex usr/lib/agentos/codex \
	var/lib/agentos-codex/tmp var/lib/agentos-work tmp proc dev sys run/agentos root
# Only what a headless turn needs: the CLI, the helper it starts from beside its binary, its
# bundled bwrap and ripgrep. The voice libraries and zsh are left out.
tar -xzf "$work/codex.tgz" -C opt/codex --strip-components=1 \
	"$VENDOR/codex-package.json" "$VENDOR/bin/codex" "$VENDOR/bin/codex-code-mode-host" \
	"$VENDOR/codex-resources/bwrap" "$VENDOR/codex-path/rg"
v=/opt/codex/vendor/x86_64-unknown-linux-musl
ln -s "$v/bin/codex" usr/local/bin/codex
cp "opt/codex/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap" usr/bin/bwrap
chmod 0755 usr/bin/bwrap

# The managed layers (they beat CODEX_HOME and the command line: ASSUMPTIONS C1, C12), the tool
# wrapper and the launch spec, all root-owned.
install -m 0644 "$here/managed_config.toml" etc/codex/managed_config.toml
install -m 0644 "$here/requirements.toml" etc/codex/requirements.toml
install -m 0755 "$here/agentos-toolsh" usr/local/bin/agentos-toolsh
install -m 0644 "$here/launch.json" usr/lib/agentos/codex/launch.json

# The in-worker forwarder (#1014): loopback 18432 to /run/agentos/route.sock, the only route the
# CLI is pointed at. FORWARDER_BIN=<file> installs a prebuilt static binary; otherwise it is built
# from this repository with the host's Go.
if [ -n "${FORWARDER_BIN:-}" ]; then
	install -m 0755 "$FORWARDER_BIN" usr/local/bin/agentos-codex-forwarder
else
	(cd "$here/../../broker" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid=' \
		-o "$out/usr/local/bin/agentos-codex-forwarder" ./egress/cmd/agentos-codex-forwarder)
fi

# The host's shell and a few tools, with every library they load (the CLI itself is static).
copy() {
	for f in "$@"; do
		d=$(dirname "$f")
		mkdir -p ".$d"
		cp -L "$f" ".$f"
	done
}
for b in /bin/sh /bin/bash /usr/bin/env /usr/bin/uname /usr/bin/id /bin/ls /bin/cat /bin/mkdir /bin/rm /bin/sleep; do
	[ -e "$b" ] || continue
	copy "$b"
	copy $(ldd "$b" | awk '/=>/ {print $3} /^\t\// {print $1}')
done

printf 'root:x:0:0:root:/root:/bin/sh\n' >etc/passwd
printf 'root:x:0:\n' >etc/group
printf '127.0.0.1 localhost\n::1 localhost\n' >etc/hosts
: >etc/resolv.conf # no resolver: the machine has no network but its socket
echo "rootfs ready: $out ($(du -sh "$out" | cut -f1))"
