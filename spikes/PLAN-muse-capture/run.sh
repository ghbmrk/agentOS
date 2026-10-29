#!/bin/bash
# #1379 slice (b): supervised capture of Muse Code's traffic on the owner's own plan, as S8-live
# (#809) did for Codex. Runs on macOS or Linux. record.py (a mitmproxy addon) sits between the CLI
# and Meta and writes a shapes-only log; model calls are refused unless a turn is granted, so the
# default run spends no plan usage. The CLI runs with its own HOME under $W, so its login is kept
# apart from the owner's own and is logged out and deleted by `clean`.
#
# Usage: run.sh setup | test | rec PHASE [TURNS] | reverse PHASE URL [TURNS] | muse ARGS... |
#               scan | stop | clean
#   setup    venv with the pinned mitmproxy, the recorder's CA, a CA bundle (certifi + that CA),
#            and this run's canary token
#   canary   print the canary; every test prompt ends with it, and the recorder refuses any
#            request or websocket message that carries it unless a turn is granted
#   test     record.py's tests
#   rec      (re)start the recorder as an HTTPS proxy on 127.0.0.1:18433, labelling records PHASE;
#            TURNS model calls are let through (default 0)
#   reverse  the same as a plain-HTTP reverse proxy to URL, for a CLI base-URL override
#   muse     run the CLI through the recorder with the isolated HOME and CA bundle
#   scan     fail if the log holds anything token-, email- or id-like; print hosts and paths
#   stop     stop the recorder
#   clean    log the CLI out, stop the recorder, delete the isolated HOME and the recorder's CA;
#            $W/log.jsonl is kept for RESULT.md (`clean all` deletes it too)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
W=${MUSE_CAP_DIR:-${TMPDIR:-/tmp}/agentos-muse-capture}
W=${W%/}
PORT=18433
MITM=12.3.1
mkdir -p "$W"
chmod 700 "$W"

stop() {
	[ -f "$W/rec.pid" ] && kill "$(cat "$W/rec.pid")" 2>/dev/null || true
	rm -f "$W/rec.pid"
}

start() { # start PHASE TURNS MODE-ARGS...
	phase=$1 turns=$2; shift 2
	[ -s "$W/canary" ] || { echo "run.sh: no canary in $W/canary; run setup first" >&2; exit 1; }
	stop
	MUSE_CAP_LOG="$W/log.jsonl" MUSE_CAP_PHASE="$phase" MUSE_CAP_ALLOW_TURNS="$turns" MUSE_CAP_CANARY="$(cat "$W/canary")" \
		"$W/venv/bin/mitmdump" -q --listen-host 127.0.0.1 -p $PORT --set confdir="$W/mitm" \
		--set connection_strategy=lazy "$@" -s "$here/record.py" >"$W/rec.err" 2>&1 &
	echo $! >"$W/rec.pid"
	for _ in $(seq 50); do
		(echo >/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && { echo "recorder up: phase=$phase turns=$turns"; return; }
		sleep 0.1
	done
	echo "run.sh: recorder did not start; see $W/rec.err" >&2; exit 1
}

case ${1:-} in
setup)
	[ -s "$W/canary" ] || echo "mcapcanary$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" >"$W/canary"
	[ -x "$W/venv/bin/mitmdump" ] || { python3 -m venv "$W/venv" && "$W/venv/bin/pip" -q install "mitmproxy==$MITM" pytest; }
	if [ ! -f "$W/mitm/mitmproxy-ca-cert.pem" ]; then
		start setup 0
		sleep 1
		stop
	fi
	cat "$("$W/venv/bin/python" -I -m certifi)" "$W/mitm/mitmproxy-ca-cert.pem" >"$W/ca-bundle.pem"
	mkdir -p -m 700 "$W/home"
	"$W/venv/bin/mitmdump" --version | head -1
	echo "muse: $(command -v muse || echo 'not installed')"
	command -v muse >/dev/null && { muse --version || true; file -L "$(command -v muse)" | cut -c1-160; }
	;;
canary)
	cat "$W/canary"
	;;
test)
	cd "$here" && MUSE_CAP_LOG="$W/test.jsonl" "$W/venv/bin/python" -I -m pytest -q record_test.py
	;;
rec)
	start "$2" "${3:-0}"
	;;
reverse)
	start "$2" "${4:-0}" --mode "reverse:$3"
	;;
muse)
	shift
	P=http://127.0.0.1:$PORT
	# A fresh HOME and XDG dirs keep the CLI's config and login under $W. The CA bundle is offered
	# through every variable a common TLS stack reads; a client that ignores them shows up as
	# tls-refused records in the log.
	env HOME="$W/home" XDG_CONFIG_HOME="$W/home/.config" XDG_DATA_HOME="$W/home/.local/share" \
		XDG_CACHE_HOME="$W/home/.cache" XDG_STATE_HOME="$W/home/.local/state" \
		HTTPS_PROXY=$P HTTP_PROXY=$P ALL_PROXY=$P https_proxy=$P http_proxy=$P all_proxy=$P \
		NO_PROXY= no_proxy= SSL_CERT_FILE="$W/ca-bundle.pem" NODE_EXTRA_CA_CERTS="$W/ca-bundle.pem" \
		REQUESTS_CA_BUNDLE="$W/ca-bundle.pem" CURL_CA_BUNDLE="$W/ca-bundle.pem" \
		muse "$@"
	;;
scan)
	"$W/venv/bin/python" -I - "$W/log.jsonl" <<'EOF'
import json, re, sys
bad = re.compile(r"[A-Za-z0-9_\-]{24,}|@|eyJ[A-Za-z0-9_-]{8,}")
hits, seen = [], {}
def walk(v, where):
    if isinstance(v, dict):
        for k, x in v.items():
            walk(k, where); walk(x, where)
    elif isinstance(v, list):
        for x in v: walk(x, where)
    elif isinstance(v, str) and (bad.search(v) or any(re.search(r"\d", r) and re.search(r"[A-Za-z]", r)
                                                     for r in re.findall(r"[A-Za-z0-9]{10,}", v))):
        hits.append((where, v[:12] + "..."))
    elif isinstance(v, int) and not isinstance(v, bool) and v > 10**9 and where != "t":
        hits.append((where, "large number"))
for n, line in enumerate(open(sys.argv[1]), 1):
    r = json.loads(line)
    for k, v in r.items():
        if k != "t": walk(v, k)
    if r["dir"] in ("req", "tls-refused", "connect"):
        key = (r.get("phase"), r.get("host") or r.get("sni"), r.get("method", r["dir"]), r.get("path", ""))
        seen[key] = seen.get(key, 0) + 1
for (ph, h, m, p), c in sorted(seen.items(), key=str):
    print(f"{ph}\t{h}\t{m}\t{p}\t{c}")
turns = [r for r in map(json.loads, open(sys.argv[1])) if r.get("model_call") or r.get("opaque")]
for ph in sorted({r.get("phase") for r in turns}, key=str):
    t = [r for r in turns if r.get("phase") == ph]
    print(f"model calls in {ph}: {len(t)}, blocked: {sum(1 for r in t if r.get('blocked'))}")
if not turns:
    print("model calls: none")
canary = open(sys.argv[1].rsplit("/", 1)[0] + "/canary").read().strip()
if canary and canary in open(sys.argv[1]).read():
    hits.append(("log", "canary"))
if hits:
    print(f"scan: {len(hits)} suspect value(s), first: {hits[:3]}", file=sys.stderr); sys.exit(1)
print("scan: clean")
EOF
	;;
stop)
	stop
	;;
clean)
	command -v muse >/dev/null && [ -d "$W/home" ] && "$0" muse logout >/dev/null 2>&1 || true
	stop
	rm -rf "$W/home" "$W/mitm" "$W/ca-bundle.pem" "$W/rec.err" "$W/test.jsonl"
	[ "${2:-}" = all ] && rm -rf "$W"
	echo "cleaned $W"
	;;
*)
	sed -n '2,21p' "$0"; exit 2
	;;
esac
