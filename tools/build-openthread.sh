#!/bin/sh
# Builds the enforcer's Thread stack, OpenThread's ot-daemon (D-231,
# spikes/ENF-radio), from the commit pinned in
# broker/enforcer/radio/thread/openthread.pin: border routing, the SRP
# server and its advertising proxy, the DNS-SD server and discovery proxy,
# and OpenThread's own mDNS, with no otbr-agent, Avahi, D-Bus or web UI.
# Its command socket's base name is relative, so it lives in the run
# directory the stack runs in (thread.Socket); its settings go where
# --data-path says (thread.DaemonArgs). It is linked static, since its
# view holds no loader (confine.Thread, #4369), and position-independent
# (-static-pie), so it keeps ASLR. The image (slice m) installs the
# result.
#
# With --sim it also builds OpenThread's simulated RCP and FTD node, which
# radio::TestSrpReachesController runs. Needs git, cmake, ninja and a C++
# compiler. Usage: build-openthread.sh OUTDIR [--sim]
set -eu

# Its mbedtls submodule (and that one's framework submodule) is pinned by
# that commit's tree.
PIN=$(dirname "$0")/../broker/enforcer/radio/thread/openthread.pin
OT_COMMIT=$(sed -n 's/^commit \([0-9a-f]\{40\}\)$/\1/p' "$PIN")
[ -n "$OT_COMMIT" ]

OUT=$1
SIM=${2:-}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
git init -q "$W/src"
git -C "$W/src" fetch -q --depth 1 https://github.com/openthread/openthread "$OT_COMMIT"
git -C "$W/src" checkout -q FETCH_HEAD
[ "$(git -C "$W/src" rev-parse HEAD)" = "$OT_COMMIT" ]
git -C "$W/src" submodule update -q --init --recursive --depth 1 third_party/mbedtls/repo

SOCK='-DOPENTHREAD_POSIX_CONFIG_DAEMON_SOCKET_BASENAME=\"openthread-%s\"'
cmake -S "$W/src" -B "$W/posix" -GNinja -DCMAKE_BUILD_TYPE=Release \
	-DOT_PLATFORM=posix -DOT_DAEMON=ON -DOT_READLINE=OFF -DOT_FTD=ON -DOT_MTD=OFF -DOT_RCP=OFF \
	-DOT_PLATFORM_NETIF=ON -DOT_PLATFORM_UDP=ON \
	-DOT_BORDER_ROUTER=ON -DOT_BORDER_ROUTING=ON -DOT_SLAAC=ON -DOT_SERVICE=ON -DOT_NETDATA_PUBLISHER=ON \
	-DOT_SRP_SERVER=ON -DOT_SRP_ADV_PROXY=ON -DOT_MDNS=ON \
	-DOT_DNSSD_SERVER=ON -DOT_DNSSD_DISCOVERY_PROXY=ON -DOT_ECDSA=ON \
	-DCMAKE_C_FLAGS="$SOCK" -DCMAKE_CXX_FLAGS="$SOCK" -DCMAKE_EXE_LINKER_FLAGS=-static-pie >"$W/posix.log" 2>&1 || { cat "$W/posix.log"; exit 1; }
ninja -C "$W/posix" ot-daemon >>"$W/posix.log" 2>&1 || { tail -100 "$W/posix.log"; exit 1; }
mkdir -p "$OUT"
install -m 0755 "$W/posix/src/posix/ot-daemon" "$OUT/ot-daemon"

if [ "$SIM" = --sim ]; then
	cmake -S "$W/src" -B "$W/sim" -GNinja -DCMAKE_BUILD_TYPE=Release \
		-DOT_PLATFORM=simulation -DOT_FTD=ON -DOT_MTD=OFF -DOT_RCP=ON \
		-DOT_SRP_CLIENT=ON -DOT_ECDSA=ON -DOT_SLAAC=ON -DOT_SERVICE=ON >"$W/sim.log" 2>&1 || { cat "$W/sim.log"; exit 1; }
	ninja -C "$W/sim" ot-cli-ftd ot-rcp >>"$W/sim.log" 2>&1 || { tail -100 "$W/sim.log"; exit 1; }
	install -m 0755 "$W/sim/examples/apps/cli/ot-cli-ftd" "$OUT/ot-cli-ftd"
	install -m 0755 "$W/sim/examples/apps/ncp/ot-rcp" "$OUT/ot-rcp"
fi
