#!/usr/bin/env bash
# Run one OpenClaw agent turn inside a network namespace whose only reachable
# endpoint is the stub broker; DNS goes to a logging NXDOMAIN sink. Usage: run_guest.sh <out-dir> <message> [extra openclaw args]
# Needs: root (unshare -n), strace, Node >= 24.16 on PATH, OPENCLAW_BIN.
set -u
here=$(cd "$(dirname "$0")" && pwd)
out=$1; msg=$2; shift 2
mkdir -p "$out"
exec unshare -n -m bash -c '
  set -u
  python3 "$0/netns_up.py"
  echo "nameserver 127.0.0.1" >"$1/resolv.conf"; mount --bind "$1/resolv.conf" /etc/resolv.conf
  python3 "$0/dns_sink.py" "$1/dns.jsonl" & dpid=$!
  export HOME="$1/home" OPENCLAW_CONFIG_PATH="$1/home/openclaw.json5" \
    OPENCLAW_NO_AUTO_UPDATE=1 OPENCLAW_DISABLE_BONJOUR=1 DO_NOT_TRACK=1
  mkdir -p "$HOME"; cp "$0/openclaw.json5" "$OPENCLAW_CONFIG_PATH"
  python3 "$0/stub_broker.py" --log "$1/broker.jsonl" & bpid=$!
  sleep 0.5
  python3 "$0/measure.py" "$1/time.txt" \
    strace -f -qq -e trace=connect -o "$1/connect.strace" \
    timeout 240 "$OPENCLAW_BIN" agent --local --message "$2" "${@:3}" >"$1/stdout.txt" 2>"$1/stderr.txt"
  echo "rc=$?" >"$1/rc.txt"
  kill $bpid $dpid
' "$here" "$out" "$msg" "$@"
