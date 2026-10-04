#!/usr/bin/env bash
# Run the OpenClaw gateway as the guest inside a network namespace whose only
# reachable endpoint is the stub broker, then deliver one owner message the way a
# broker would: POST to the gateway's OpenAI-compatible endpoint.
# DNS goes to a local sink that logs names and answers NXDOMAIN.
# Usage: run_gateway.sh <out-dir> <message>. Needs root, strace, Node >= 24.16, OPENCLAW_BIN.
set -u
here=$(cd "$(dirname "$0")" && pwd)
exec unshare -n -m bash -c '
  set -u
  mkdir -p "$1"
  python3 "$0/netns_up.py"
  echo "nameserver 127.0.0.1" >"$1/resolv.conf"; mount --bind "$1/resolv.conf" /etc/resolv.conf
  python3 "$0/dns_sink.py" "$1/dns.jsonl" 2>"$1/dns.err" & dpid=$!
  export HOME="$1/home" OPENCLAW_CONFIG_PATH="$1/home/openclaw.json5" \
    OPENCLAW_NO_AUTO_UPDATE=1 OPENCLAW_DISABLE_BONJOUR=1 DO_NOT_TRACK=1 \
    OPENCLAW_GATEWAY_TOKEN=s4-local-inbound-token
  mkdir -p "$HOME"; cp "$0/openclaw.json5" "$OPENCLAW_CONFIG_PATH"
  python3 "$0/stub_broker.py" --log "$1/broker.jsonl" & bpid=$!
  setsid strace -f -qq -e trace=connect,sendto,sendmsg -o "$1/net.strace" \
    "$OPENCLAW_BIN" gateway run --port 18789 >"$1/gw.stdout" 2>"$1/gw.stderr" & gpid=$!
  t0=$(date +%s.%N)
  for i in $(seq 240); do curl -s -o /dev/null -m 2 http://127.0.0.1:18789/ && break; sleep 0.5; done
  t1=$(date +%s.%N)
  curl -s -m 200 http://127.0.0.1:18789/v1/chat/completions \
    -H "Authorization: Bearer $OPENCLAW_GATEWAY_TOKEN" -H "Content-Type: application/json" \
    -d "{\"model\":\"openclaw\",\"user\":\"owner-sms\",\"messages\":[{\"role\":\"user\",\"content\":\"$2\"}]}" >"$1/reply.json"
  t2=$(date +%s.%N)
  echo "gateway ready $(echo "$t1-$t0" | bc) s; turn $(echo "$t2-$t1" | bc) s" >"$1/time.txt"
  ps -o rss=,comm= -g $gpid | grep -v strace | awk "{s+=\$1} END {print s \" KB RSS, gateway and its children, after the turn\"}" >>"$1/time.txt"
  for p in $(ps -o pid=,comm= -g $gpid | grep -v strace | awk "{print \$1}"); do
    awk "/^Pss:/ {print \$2}" /proc/$p/smaps_rollup; done | awk "{s+=\$1} END {print s \" KB PSS, same processes (shared pages split)\"}" >>"$1/time.txt"
  kill -- -$gpid; kill $bpid $dpid
' "$here" "$1" "$2"
