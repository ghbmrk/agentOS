#!/bin/sh
# C1 first check: how the pinned Claude Code CLI takes a pasted setup-token
# headlessly, and what it writes to disk. Synthetic canary only; every byte of
# egress goes to the S8 stub. Usage: CLAUDE=/path/to/claude run.sh
set -u
D=$(cd "$(dirname "$0")" && pwd); S8=$D/../S8-provider-workers
CLAUDE=${CLAUDE:-claude}; PORT=${PORT:-18432}
TOK=sk-ant-oat01-PLACEHOLDER-S8          # the stub's canary, not a real token
R=$D/results; mkdir -p "$R"
python3 "$S8/stub_anthropic.py" "$PORT" "$R/stub.jsonl" 2>/dev/null & SP=$!
trap 'kill $SP 2>/dev/null' EXIT; sleep 0.5
run() { # $1 case name; rest: extra env; stdin/fd set by caller
  name=$1; shift; H=$(mktemp -d); mkdir -p "$H/work"; : > "$R/stub.jsonl"
  (cd "$H/work" && env -i PATH="$PATH" HOME="$H" TERM=dumb "$@" \
    ANTHROPIC_BASE_URL="http://127.0.0.1:$PORT" CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    HTTPS_PROXY="http://127.0.0.1:$PORT" HTTP_PROXY="http://127.0.0.1:$PORT" NO_PROXY=127.0.0.1 \
    timeout 90 "$CLAUDE" -p "write the S8 marker" --allowedTools Bash --max-turns 3 \
    ${FLAGS:-} 3<"${FDFILE:-/dev/null}" </dev/null >"$R/$name.out" 2>&1; echo "exit=$?" >>"$R/$name.out")
  auth=$(grep -o '"authorization": "[^"]*"' "$R/stub.jsonl" | sort | uniq -c | tr '\n' ' ')
  calls=$(grep -c '/v1/messages' "$R/stub.jsonl")
  files=$(cd "$H" && find . -type f ! -path './work/*' | sort | tr '\n' ' ')
  hits=$(grep -rl "$TOK" "$H" 2>/dev/null | sed "s#$H#~#" | tr '\n' ' ')
  echo "$name | messages=$calls | auth: ${auth:-none} | token on disk: ${hits:-none} | $(tail -1 "$R/$name.out")"
  echo "  files: $files"; rm -rf "$H"
}
"$CLAUDE" --version
run env-var CLAUDE_CODE_OAUTH_TOKEN=$TOK
printf '%s\n' "$TOK" > "$R/.fdtok"; FDFILE=$R/.fdtok run fd CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3
rm -f "$R/.fdtok"
FLAGS=--bare run bare CLAUDE_CODE_OAUTH_TOKEN=$TOK
# W1 probe, from outside: is the canary in the running CLI's /proc environ or fds?
probe() { # $1 case; rest: env
  name=$1; shift; H=$(mktemp -d); : > "$R/stub.jsonl"
  (cd "$H" && env -i PATH="$PATH" HOME="$H" TERM=dumb "$@" ANTHROPIC_BASE_URL="http://127.0.0.1:$PORT" \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 timeout 20 "$CLAUDE" -p hi 3<"${FDFILE:-/dev/null}" </dev/null >/dev/null 2>&1) &
  CP=$!; sleep 3; seen=""
  for p in $(pgrep -f "^$CLAUDE -p hi"); do
    grep -qa PLACEHOLDER-S8 /proc/$p/environ 2>/dev/null && seen="$seen environ"
    for f in /proc/$p/fd/*; do { [ -f "$f" ] || [ -p "$f" ]; } && timeout 1 grep -qa PLACEHOLDER-S8 "$f" 2>/dev/null && seen="$seen fd:${f##*/}=$(readlink "$f" | sed "s#$H#~#")"; done
  done; wait $CP; echo "$name | canary sent: $(grep -c "\"canary\": true" "$R/stub.jsonl") | canary visible in /proc of the CLI:${seen:- nowhere}"; rm -rf "$H"
}
kill $SP; sleep 0.3; python3 "$D/stub401.py" "$PORT" "$R/stub.jsonl" hang 2>/dev/null & SP=$!; sleep 0.5
probe probe-env CLAUDE_CODE_OAUTH_TOKEN=$TOK
printf '%s\n' "$TOK" > "$R/.fdtok"; FDFILE=$R/.fdtok probe probe-fd-file CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3
rm -f "$R/.fdtok"; mkfifo "$R/.fdpipe"; (printf '%s\n' "$TOK" > "$R/.fdpipe" &)
FDFILE=$R/.fdpipe probe probe-fd-pipe CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3; rm -f "$R/.fdpipe"
# Error path: revoked or wrong token (stub answers 401)
kill $SP; sleep 0.3; python3 "$D/stub401.py" "$PORT" "$R/stub.jsonl" & SP=$!; sleep 0.5
run revoked CLAUDE_CODE_OAUTH_TOKEN=$TOK
