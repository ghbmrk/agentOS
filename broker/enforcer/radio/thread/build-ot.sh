#!/bin/sh
# Builds the enforcer's Thread stack, OpenThread's ot-daemon (D-231,
# spikes/ENF-radio), from the pinned commit below: border routing, the SRP
# server and its advertising proxy, the DNS-SD server and discovery proxy,
# and OpenThread's own mDNS, with no otbr-agent, Avahi, D-Bus or web UI.
# Its command socket's base name is relative, so it lives in the state
# directory the stack runs in (thread.Socket); its settings go where
# --data-path says (thread.DaemonArgs). The image (slice m) installs the
# result; this file is the build pin.
#
# With --sim it also builds OpenThread's simulated RCP and FTD node, which
# radio::TestSrpReachesController runs. Needs git, cmake, ninja and a C++
# compiler. Usage: build-ot.sh OUTDIR [--sim]
set -eu

# openthread/openthread main at 2026-10-29; its mbedtls submodule is pinned
# by this commit's tree.
OT_COMMIT=e577777c308f6c87e5da3056239231a8fc147cb2

OUT=$1
SIM=${2:-}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
git init -q "$W/src"
git -C "$W/src" fetch -q --depth 1 https://github.com/openthread/openthread "$OT_COMMIT"
git -C "$W/src" checkout -q FETCH_HEAD
[ "$(git -C "$W/src" rev-parse HEAD)" = "$OT_COMMIT" ]
git -C "$W/src" submodule update -q --init --depth 1 third_party/mbedtls/repo

SOCK='-DOPENTHREAD_POSIX_CONFIG_DAEMON_SOCKET_BASENAME=\"openthread-%s\"'
cmake -S "$W/src" -B "$W/posix" -GNinja -DCMAKE_BUILD_TYPE=Release \
	-DOT_PLATFORM=posix -DOT_DAEMON=ON -DOT_READLINE=OFF -DOT_FTD=ON -DOT_MTD=OFF -DOT_RCP=OFF \
	-DOT_PLATFORM_NETIF=ON -DOT_PLATFORM_UDP=ON \
	-DOT_BORDER_ROUTING=ON -DOT_SRP_SERVER=ON -DOT_SRP_ADV_PROXY=ON -DOT_MDNS=ON \
	-DOT_DNSSD_SERVER=ON -DOT_DNSSD_DISCOVERY_PROXY=ON -DOT_ECDSA=ON \
	-DCMAKE_C_FLAGS="$SOCK" -DCMAKE_CXX_FLAGS="$SOCK" >"$W/posix.log" 2>&1 || { cat "$W/posix.log"; exit 1; }
ninja -C "$W/posix" ot-daemon >>"$W/posix.log" 2>&1 || { tail -100 "$W/posix.log"; exit 1; }
mkdir -p "$OUT"
install -m 0755 "$W/posix/src/posix/ot-daemon" "$OUT/ot-daemon"

if [ "$SIM" = --sim ]; then
	cmake -S "$W/src" -B "$W/sim" -GNinja -DCMAKE_BUILD_TYPE=Release \
		-DOT_PLATFORM=simulation -DOT_FTD=ON -DOT_MTD=OFF -DOT_RCP=ON \
		-DOT_SRP_CLIENT=ON -DOT_ECDSA=ON >"$W/sim.log" 2>&1 || { cat "$W/sim.log"; exit 1; }
	ninja -C "$W/sim" ot-cli-ftd ot-rcp >>"$W/sim.log" 2>&1 || { tail -100 "$W/sim.log"; exit 1; }
	install -m 0755 "$W/sim/examples/apps/cli/ot-cli-ftd" "$OUT/ot-cli-ftd"
	install -m 0755 "$W/sim/examples/apps/ncp/ot-rcp" "$OUT/ot-rcp"
fi
