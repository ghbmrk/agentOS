#!/bin/sh
# Q1+Q2 (Codex CLI): `codex exec` headless with its shell tool on, ChatGPT
# sign-in mode, auth.json holding only placeholder tokens, the backend pointed
# at the stub. Other egress is refused through HTTPS_PROXY and logged.
set -eu
D=$(cd "$(dirname "$0")" && pwd)
CODEX=${CODEX:-codex}
W=$(mktemp -d); LOG=${LOG:-$D/results/codex_stub.jsonl}; PORT=${PORT:-18432}
mkdir -p "$D/results"; : > "$LOG"
STUB_MODE=${STUB_MODE:-} python3 "$D/stub_codex.py" "$PORT" "$LOG" 2>/dev/null & SP=$!
trap 'kill $SP 2>/dev/null; rm -rf "$W"' EXIT
sleep 0.5
mkdir -p "$W/codex" "$W/work"
python3 "$D/fake_codex_auth.py" > "$W/codex/auth.json"
cat > "$W/codex/config.toml" <<TOML
chatgpt_base_url = "http://127.0.0.1:$PORT/backend-api/"
${EXTRA_TOML:-}
TOML
cd "$W/work"; git init -q .
env -i PATH="$PATH" HOME="$W" CODEX_HOME="$W/codex" TERM=dumb \
  HTTPS_PROXY="http://127.0.0.1:$PORT" HTTP_PROXY="http://127.0.0.1:$PORT" NO_PROXY=127.0.0.1 \
  timeout 120 "$CODEX" exec --json --sandbox workspace-write --skip-git-repo-check \
    "write the S8 marker" < /dev/null \
  > "$D/results/codex_stream.jsonl" 2> "$D/results/codex_stderr.txt" || echo "exit=$?"
find "$W/codex/sessions" -name "*.jsonl" -exec cat {} + > "$D/results/codex_rollout.jsonl" 2>/dev/null || true
echo "marker: $(cat s8_marker.txt 2>/dev/null || echo MISSING)"
