#!/bin/bash
# #1379 slice (b): supervised capture of Muse Code's traffic on the owner's own plan, as S8-live
# (#809) did for Codex. Runs on macOS or Linux. record.py is a default-deny gate (a mitmproxy
# addon) between the CLI and Meta: it refuses every request not on the allow file, kills every
# non-HTTP flow, and writes a shapes-only log. The CLI runs with its own HOME and an empty working
# directory under $W, so its login is kept apart and `clean` logs it out and deletes it.
#
# Usage: run.sh setup | test | rec PHASE [strict] | refused | allow 'METHOD HOST PATH' |
#               muse ARGS... | scan | stop | clean [all]
#   setup    venv with the pinned mitmproxy, the gate's CA, a CA bundle (certifi + that CA)
#   test     record.py's tests
#   rec      (re)start the gate on 127.0.0.1:18433, labelling records PHASE. `strict` is for a
#            phase that may carry a prompt: only bodyless GETs of URLs already seen pass
#   refused  the distinct refused requests (method, host, normalised path, reason), to review
#   allow    add one line to the allow file (no-prompt phases only; see README for what may go)
#   muse     run the CLI through the gate with the isolated HOME and CA bundle
#   scan     fail if the log holds anything token-, email- or id-like; print per-phase counts
#   stop     stop the gate
#   clean    log the CLI out, stop the gate, delete the isolated HOME, CA and seen URLs;
#            $W/log.jsonl is kept for RESULT.md (`clean all` deletes everything)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
W=${MUSE_CAP_DIR:-${TMPDIR:-/tmp}/agentos-muse-capture}
W=${W%/}
PORT=18433
MITM=12.3.1
mkdir -p "$W"
chmod 700 "$W"

stop() {
	if [ -f "$W/rec.pid" ]; then
		pid=$(cat "$W/rec.pid")
		kill "$pid" 2>/dev/null || true
		for _ in $(seq 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
	fi
	rm -f "$W/rec.pid"
}

start() { # start PHASE STRICT
	stop
	touch "$W/allow.txt" "$W/seen.txt"
	MUSE_CAP_LOG="$W/log.jsonl" MUSE_CAP_PHASE="$1" MUSE_CAP_STRICT="$2" \
		MUSE_CAP_ALLOW="$W/allow.txt" MUSE_CAP_SEEN="$W/seen.txt" \
		"$W/venv/bin/mitmdump" -q --listen-host 127.0.0.1 -p $PORT --set confdir="$W/mitm" \
		--set connection_strategy=lazy -s "$here/record.py" >"$W/rec.err" 2>&1 &
	echo $! >"$W/rec.pid"
	for _ in $(seq 50); do
		(echo >/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && { echo "gate up: phase=$1 strict=${2:-0}"; return; }
		sleep 0.1
	done
	echo "run.sh: gate did not start; see $W/rec.err" >&2; exit 1
}

case ${1:-} in
setup)
	[ -x "$W/venv/bin/mitmdump" ] || { python3 -m venv "$W/venv" && "$W/venv/bin/pip" -q install "mitmproxy==$MITM" pytest; }
	if [ ! -f "$W/mitm/mitmproxy-ca-cert.pem" ]; then
		start setup 1
		sleep 1
		stop
	fi
	cat "$("$W/venv/bin/python" -I -m certifi)" "$W/mitm/mitmproxy-ca-cert.pem" >"$W/ca-bundle.pem"
	mkdir -p -m 700 "$W/home" "$W/work"
	"$W/venv/bin/mitmdump" --version | head -1
	echo "muse: $(command -v muse || echo 'not installed')"
	command -v muse >/dev/null && { muse --version || true; file -L "$(command -v muse)" | cut -c1-160; }
	;;
test)
	cd "$here" && "$W/venv/bin/python" -I -m pytest -q record_test.py
	;;
rec)
	if [ "${3:-}" = strict ]; then start "$2" 1; else start "$2" ""; fi
	;;
refused)
	jq -r 'select(.refused) | "\(.refused)\t\(.method) \(.host) \(.path)"' "$W/log.jsonl" | sort | uniq -c
	;;
allow)
	echo "$2" | grep -Eq '^(GET|HEAD|POST|PUT|PATCH|DELETE) [A-Za-z0-9.-]+(:[0-9]+)? /[^ ]*$' || { echo "run.sh: want 'METHOD HOST PATH'" >&2; exit 2; }
	echo "$2" >>"$W/allow.txt"
	;;
muse)
	shift
	P=http://127.0.0.1:$PORT
	# A fresh HOME, XDG dirs and an empty working directory keep the CLI's config, login and
	# workspace under $W. The CA bundle is offered through every variable a common TLS stack
	# reads; a client that ignores them shows up as tls-refused records.
	cd "$W/work"
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
hits, counts = [], {}
def walk(v, where):
    if isinstance(v, dict):
        for k, x in v.items():
            walk(k, where); walk(x, where)
    elif isinstance(v, list):
        for x in v: walk(x, where)
    elif isinstance(v, str) and (bad.search(v) or any(re.search(r"\d", r) and re.search(r"[A-Za-z]", r)
                                                     for r in re.findall(r"[A-Za-z0-9]{10,}", v))):
        hits.append((where, v[:12] + "..."))
    elif isinstance(v, int) and not isinstance(v, bool) and v > 10**9:
        hits.append((where, "large number"))
for line in open(sys.argv[1]):
    r = json.loads(line)
    for k, v in r.items():
        if k != "t": walk(v, k)
    kind = "refused" if r.get("refused") else r["dir"]
    c = counts.setdefault(r.get("phase"), {})
    c[kind] = c.get(kind, 0) + 1
for ph, c in counts.items():
    print(ph, " ".join(f"{k}={v}" for k, v in sorted(c.items())))
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
	rm -rf "$W/home" "$W/work" "$W/mitm" "$W/ca-bundle.pem" "$W/rec.err" "$W/seen.txt"
	[ "${2:-}" = all ] && rm -rf "$W"
	echo "cleaned $W"
	;;
*)
	sed -n '2,24p' "$0"; exit 2
	;;
esac
