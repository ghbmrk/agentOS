#!/bin/sh
# Builds the root file system of the Codex provider worker (S8-W1, #807; CRED-5 broker-held):
# the pinned official Codex CLI, its managed config and requirements, the launch spec, and the
# shell and tools its tool subprocesses need. It holds no login: no auth.json is written here
# (#1015 writes the placeholder into CODEX_HOME at machine create).
#
# Usage: build-rootfs.sh OUT_DIR
# Run as root (chroot). Needs: Go (unless FORWARDER_BIN is set), curl (unless both tarballs are
# set), openssl, sha256sum, chroot, and GUEST_BASE, a root from image/guest-base.sh, whose /bin/sh,
# /bin/bash and coreutils are copied in with their libraries, and whose tar, xz, patch and gcc unpack
# both tarballs and patch and compile bwrap: no host tar, xz or patch runs (#5582).
# CODEX_TARBALL=<file> and BWRAP_TARBALL=<file> use local copies of the pinned tarballs instead of
# downloading them; each is still checked against its pinned hash.
# Hook for #809 (the runsc measurement of guest/codex/ASSUMPTIONS.md C1-C15): register OUT_DIR as
# an image with agentosd (-image codex=OUT_DIR) and run the measurements in a machine from it.
# broker/e2e/codex_contain_test.go (#1720) runs the pinned CLI in a machine from OUT_DIR under runsc
# and checks that its tools cannot reach the forwarder, the route socket or CODEX_HOME.
set -eu
CODEX_VERSION=0.162.1
CODEX_PKG=codex-$CODEX_VERSION-linux-x64
CODEX_URL=https://registry.npmjs.org/@openai/codex/-/$CODEX_PKG.tgz
# npm's published integrity for the tarball (registry.npmjs.org/@openai/codex/0.162.1-linux-x64).
CODEX_INTEGRITY=sha512-cjK2mdHIfEepZ1lQ1MX3aTQC+8ncIsvnacl/6vI2dIIcfP8/MrhTQ2+qRlkXFNDzJSj1d36quIszP+3/4CUJWQ==
VENDOR=package/vendor/x86_64-unknown-linux-musl
# The bubblewrap release the CLI vendors, rebuilt with bwrap-loopback.patch (#1720): under runsc
# every new network namespace already has 127.0.0.1/8 on lo, and stock bwrap dies on that EEXIST.
BWRAP_VERSION=0.11.2
BWRAP_URL=https://github.com/containers/bubblewrap/releases/download/v$BWRAP_VERSION/bubblewrap-$BWRAP_VERSION.tar.xz
BWRAP_SHA256=69abc30005d2186baf7737feacd8da35633b93cf5af38838ecff17c5f8e924f6

here=$(cd "$(dirname "$0")" && pwd)
# A fresh directory only: the image is exactly what this script writes.
if [ -e "$1" ] && [ -n "$(ls -A "$1")" ]; then
	echo "build-rootfs.sh: $1 is not empty" >&2
	exit 1
fi
out=$(mkdir -p "$1" && cd "$1" && pwd)
work=$(mktemp -d)
src=
trap 'rm -rf "$work" ${src:+"$src"}' EXIT

if [ -n "${CODEX_TARBALL:-}" ]; then
	cp "$CODEX_TARBALL" "$work/codex.tgz"
else
	curl -fsSLo "$work/codex.tgz" "$CODEX_URL"
fi
got=sha512-$(openssl dgst -sha512 -binary "$work/codex.tgz" | openssl base64 -A)
[ "$got" = "$CODEX_INTEGRITY" ] || { echo "codex tarball integrity $got" >&2; exit 1; }

if [ -n "${BWRAP_TARBALL:-}" ]; then
	cp "$BWRAP_TARBALL" "$work/bwrap.tar.xz"
else
	curl -fsSLo "$work/bwrap.tar.xz" "$BWRAP_URL"
fi
echo "$BWRAP_SHA256  $work/bwrap.tar.xz" | sha256sum -c --quiet - || { echo "bwrap tarball hash" >&2; exit 1; }
# Both tarballs are unpacked, and bwrap patched and compiled, inside the base at a fixed path
# removed on exit, by the base's tar, xz, patch and gcc, the last against its static libc and
# libcap, all from the image's pinned apt sources (#5571, #5582), never the build host's: two
# runners on different runner images would link different bytes. Each tarball reaches the base's
# tar on its stdin from the very file checked above. A clean environment, so nothing of the
# caller's reaches them; sh -e stops on a rejected hunk.
base=${GUEST_BASE:?set GUEST_BASE to a root from image/guest-base.sh}
src=$base/tmp/agentos-codex-build
rm -rf "$src"
mkdir -p "$src/codex" "$src/bwrap"
cp "$here/bwrap-loopback.patch" "$src/bwrap-loopback.patch"
printf '#define PACKAGE_STRING "bubblewrap %s (agentOS loopback patch)"\n' "$BWRAP_VERSION" >"$src/bwrap/config.h"
# Only what a headless turn needs leaves the CLI's tarball: the CLI, the helper it starts from
# beside its binary, its bwrap and ripgrep. The voice libraries and zsh are left out.
chroot "$base" /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C tar -xzf - -C /tmp/agentos-codex-build/codex \
	--strip-components=1 "$VENDOR/codex-package.json" "$VENDOR/bin/codex" "$VENDOR/bin/codex-code-mode-host" \
	"$VENDOR/codex-resources/bwrap" "$VENDOR/codex-path/rg" <"$work/codex.tgz"
chroot "$base" /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C sh -ec 'cd /tmp/agentos-codex-build/bwrap
	tar -xJf - --strip-components=1
	patch -p1 --quiet <../bwrap-loopback.patch
	gcc -static -O2 -D_GNU_SOURCE -I. bubblewrap.c bind-mount.c network.c utils.c -l:libcap.a -o bwrap -Wl,-t >link.trace' \
	<"$work/bwrap.tar.xz"
# The linker listed each file it read (-t), and the Debian package of each one outside the build's
# /tmp is recorded as shipped (image/guest-shipped.sh, #5572): bwrap carries their code, so the image
# vulnerability check scans them.
linked=$(sed -n 's/(.*$//; /^\/tmp\//d; /^\//p' "$src/bwrap/link.trace" | sort -u)
[ -n "$linked" ] || { echo "bwrap: the linker listed no input outside /tmp" >&2; exit 1; }
# shellcheck disable=SC2086  # one path per word
sh "$here/../../image/guest-shipped.sh" "$base" $linked

cd "$out"
mkdir -p usr/local/bin usr/bin bin lib64 etc/codex opt/codex usr/lib/agentos/codex \
	var/lib/agentos-codex/tmp var/lib/agentos-work tmp proc dev sys run/agentos root
# The CLI as unpacked in the base. Its bundled bwrap is replaced by the patched build at both paths
# the CLI looks in (PATH first, then codex-resources).
cp -a "$src/codex/." opt/codex/
v=/opt/codex/vendor/x86_64-unknown-linux-musl
ln -s "$v/bin/codex" usr/local/bin/codex
install -m 0755 "$src/bwrap/bwrap" usr/bin/bwrap
install -m 0755 "$src/bwrap/bwrap" "opt/codex/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap"

# The managed layers (they beat CODEX_HOME and the command line: ASSUMPTIONS C1, C12), the tool
# wrapper and the launch spec, all root-owned.
install -m 0644 "$here/managed_config.toml" etc/codex/managed_config.toml
install -m 0644 "$here/requirements.toml" etc/codex/requirements.toml
install -m 0755 "$here/agentos-toolsh" usr/local/bin/agentos-toolsh
install -m 0644 "$here/launch.json" usr/lib/agentos/codex/launch.json
# The pinned CLI version, which agentosd reads as the image's ImageVersion (#1877): the provider
# gate opens only when it equals the version the qualification record (#809) was taken on.
printf '%s\n' "$CODEX_VERSION" >usr/lib/agentos/cli-version
chmod 0644 usr/lib/agentos/cli-version

# The in-worker forwarder (#1014): loopback 18432 to /run/agentos/route.sock, the only route the
# CLI is pointed at. FORWARDER_BIN=<file> installs a prebuilt static binary; otherwise it is built
# from this repository with the host's Go.
if [ -n "${FORWARDER_BIN:-}" ]; then
	install -m 0755 "$FORWARDER_BIN" usr/local/bin/agentos-codex-forwarder
else
	(cd "$here/../../broker" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w -buildid=' \
		-o "$out/usr/local/bin/agentos-codex-forwarder" ./egress/cmd/agentos-codex-forwarder)
fi

# The shell and a few tools, with every library they load (the CLI itself is static), from
# GUEST_BASE, the Debian root image/guest-base.sh installs from the image's pinned apt sources, never
# from the build host (#5570).
sh "$here/../../image/guest-userland.sh" "$base" "$out" \
	/bin/sh /bin/bash /usr/bin/env /usr/bin/uname /usr/bin/id /bin/ls /bin/cat /bin/mkdir /bin/rm /bin/sleep

printf 'root:x:0:0:root:/root:/bin/sh\n' >etc/passwd
printf 'root:x:0:\n' >etc/group
printf '127.0.0.1 localhost\n::1 localhost\n' >etc/hosts
: >etc/resolv.conf # no resolver: the machine has no network but its socket
echo "rootfs ready: $out ($(du -sh "$out" | cut -f1))"
