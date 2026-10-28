#!/bin/sh
# Runs the confinement probe under both profiles. Needs root (to drop from),
# util-linux (unshare, setpriv) and Go. Prints one PASS or FAIL line per check.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
(cd "$HERE/probe" && CGO_ENABLED=0 go build -o "$W/probe" .)
chmod 0755 "$W"
mknod -m 0600 "$W/tun" c 10 200 && chown 65534:65534 "$W/tun"
mkdir -m 0700 "$W/policy" && echo '{"canary":"synthetic"}' >"$W/policy/policy.json"
DROP="setpriv --reuid 65534 --regid 65534 --clear-groups --inh-caps=-all --bounding-set=-all"

echo "== serial profile (Zigbee): private empty netns, nobody, no capabilities"
unshare -n $DROP "$W/probe" exec serial -- "$W/probe" check serial "$W/policy/policy.json"

echo "== thread profile (Thread and Matter): nobody owns a user and network namespace"
TUN="$W/tun" $DROP unshare -Urn "$W/probe" exec thread -- "$W/probe" check thread "$W/policy/policy.json"
