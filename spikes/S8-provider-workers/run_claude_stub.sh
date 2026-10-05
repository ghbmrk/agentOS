#!/bin/sh
# Q1+Q2 (Claude Code): headless, tools on, placeholder token, every byte of
# egress pointed at the stub. Anything not sent to the base URL shows up as a
# refused CONNECT in the log.
set -eu
D=$(cd "$(dirname "$0")" && pwd)
W=$(mktemp -d); LOG=${LOG:-$D/results/claude_stub.jsonl}; PORT=${PORT:-18431}
mkdir -p "$D/results"; : > "$LOG"
STUB_CMD=${STUB_CMD:-} STUB_MODE=${STUB_MODE:-} python3 "$D/stub_anthropic.py" "$PORT" "$LOG" 2>/dev/null & SP=$!
trap 'kill $SP 2>/dev/null; rm -rf "$W"' EXIT
sleep 0.5
mkdir -p "$W/home" "$W/work"
cd "$W/work"
env -i PATH="$PATH" HOME="$W/home" TERM=dumb \
  ${EXTRA_ENV:-} CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-PLACEHOLDER-S8 \
  ANTHROPIC_BASE_URL="http://127.0.0.1:$PORT" \
  HTTPS_PROXY="http://127.0.0.1:$PORT" HTTP_PROXY="http://127.0.0.1:$PORT" NO_PROXY=127.0.0.1 \
  timeout 120 claude -p "write the S8 marker" \
    --output-format stream-json --verbose \
    --allowedTools "Bash" --max-turns 4 ${CLAUDE_FLAGS:-} < /dev/null \
  > "$D/results/claude_stream.jsonl" 2>/dev/null || echo "exit=$?"
echo "marker: $(cat s8_marker.txt 2>/dev/null || echo MISSING)"
