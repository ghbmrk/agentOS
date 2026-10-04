#!/bin/sh
# Builds a root file system for the OpenClaw guest, for agent machines on a
# VM (PLAN P1-7). It is a test rig: the box's real image comes from the
# image build (P2-1). Everything it downloads is pinned by version and hash.
#
# Usage: build-rootfs.sh OUT_DIR    (MODEL=<provider model id> to set the model)
# Needs: curl, xz, sha256sum, go, and the host's /bin/sh and coreutils, which
# are copied in with their libraries for OpenClaw's exec tool.
set -eu
NODE_VERSION=v24.21.0
NODE_SHA256=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6
OPENCLAW_VERSION=2026.9.8
OPENCLAW_INTEGRITY=sha512-G+JkNUhtpDE3cXR4AEi2NyyG9fqI/T2WUSl8ZnR8AATH8Dh1kC3qYFL7wwPoZtgHiP/cszA86PEiE0PDysxb9Q==
MODEL=${MODEL:-broker-default}

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=$(mkdir -p "$1" && cd "$1" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cd "$out"
mkdir -p usr/local/bin usr/bin bin lib64 etc/openclaw opt/openclaw root tmp proc dev sys run/agentos

# Node, from the release tarball, checked against its published SHA-256.
curl -fsSLo "$work/node.tar.xz" "https://nodejs.org/dist/$NODE_VERSION/node-$NODE_VERSION-linux-x64.tar.xz"
echo "$NODE_SHA256  $work/node.tar.xz" | sha256sum -c -
n=node-$NODE_VERSION-linux-x64
tar -xJf "$work/node.tar.xz" --strip-components=1 -C usr/local "$n/bin/node" "$n/bin/npm" "$n/bin/npx" "$n/lib/node_modules/npm"

# OpenClaw, unmodified (ARC-3). Install scripts stay off, as in S4 (finding 8).
PATH="$out/usr/local/bin:$PATH" npm install --prefix opt/openclaw --ignore-scripts --no-audit --no-fund \
	--omit=dev "openclaw@$OPENCLAW_VERSION" >"$work/npm.log" 2>&1 || { cat "$work/npm.log"; exit 1; }
got=$(PATH="$out/usr/local/bin:$PATH" node -e \
	'console.log(require(process.argv[1]).packages["node_modules/openclaw"].integrity)' \
	"$out/opt/openclaw/node_modules/.package-lock.json")
[ "$got" = "$OPENCLAW_INTEGRITY" ] || { echo "openclaw integrity $got" >&2; exit 1; }
ln -sf /opt/openclaw/node_modules/.bin/openclaw usr/local/bin/openclaw

# The host's shell and a few tools, with every library they and node load.
copy() {
	for f in "$@"; do
		d=$(dirname "$f")
		mkdir -p ".$d"
		cp -L "$f" ".$f"
	done
}
for b in /bin/sh /bin/bash /usr/bin/env /usr/bin/uname /usr/bin/id /bin/ls /bin/cat /bin/mkdir /bin/rm; do
	[ -e "$b" ] || continue
	copy "$b"
	copy $(ldd "$b" | awk '/=>/ {print $3} /^\t\// {print $1}')
done
copy $(ldd usr/local/bin/node | awk '/=>/ {print $3} /^\t\// {print $1}')

# The bridge (guest code: it runs as PID 1 and starts OpenClaw).
(cd "$repo/broker" && CGO_ENABLED=0 go build -trimpath -o "$out/usr/local/bin/agentos-guest-bridge" ./cmd/agentos-guest-bridge)

sed "s/@MODEL@/$MODEL/g" "$here/openclaw.json5" >etc/openclaw/openclaw.json5
printf 'root:x:0:0:root:/root:/bin/sh\n' >etc/passwd
printf 'root:x:0:\n' >etc/group
printf '127.0.0.1 localhost\n::1 localhost\n' >etc/hosts
: >etc/resolv.conf # no resolver: the machine has no network but its socket
echo "rootfs ready: $out ($(du -sh "$out" | cut -f1))"
