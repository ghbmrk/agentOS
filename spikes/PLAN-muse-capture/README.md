# PLAN-muse-capture: supervised Muse Code capture (#1379 slice (b))

Measures Muse Code's traffic on Mark's own Muse plan so slice (c) can write `plan.Muse` from
measurements (brief: `briefs/PLAN-muse.md` slice (b), PR #3922). Same shape as S8-live (#809):
a recording proxy between the CLI and Meta, a shapes-only log, no model usage spent by default,
the login kept apart and removed afterwards. Mark's go-ahead: "Yes, Muse then Grok" on the
supervised-capture card (cmsg_01R91wiieBzMSvPKFsAJVvuKVNhu2hta1WiGwNjGyPyMPW).

**Where it runs.** On Mark's Mac through Remote Control: the cloud environment's network policy
refuses Meta's hosts (dev.meta.ai, meta.ai), and the full host list is what this capture measures,
so an allow-list cannot be written in advance. Nothing here needs admin rights or changes system
trust; `run.sh` works on Linux too.

**What is kept, and where.** `record.py` writes `$TMPDIR/agentos-muse-capture/log.jsonl` (mode 700
directory): hosts, methods, paths with id segments replaced by `{id}`, statuses, header names,
quota-like header values, and body shapes (key names, kinds, JWT header and claim names, short
enum values under known keys such as `type`, `role`, `error`). A request or client websocket
message is treated as a model call, and refused unless a turn is granted, when a `messages`,
`message`, `input`, `prompt` or `contents` key appears at any depth, including inside JSON-valued
form fields and string fields such as GraphQL `variables`. That key detector is for the log;
the guard is a canary: every test prompt ends with this run's token (`run.sh canary`), and any
request (any method, body, path, query or header) or client websocket message carrying it is
refused, whatever its shape or endpoint. The canary is looked for in the body after any HTTP
content-encoding mitmproxy decodes, percent-decoded, JSON-unescaped, and inside base64 of text.
A body it cannot fully read (an unknown or stacked content-encoding, binary, protobuf or gRPC
frames, application-level compression, base64 of compressed data, UTF-16) is refused whether or
not it carries the canary, and so is any request whose check raises an error. So a CLI that
speaks only binary bodies cannot complete the capture; that shows as `opaque` records and is a
stop. The guard does not cover traffic that bypasses the proxy (stop list below). Never a token, cookie, prompt,
reply, email or account id; `record_test.py` checks this with synthetic canaries and `run.sh scan`
re-checks the real log. No raw flow file is written. The CLI's login lives under
`$TMPDIR/agentos-muse-capture/home` and `run.sh clean` logs it out and deletes it. Only
`RESULT.md` (written from the scanned log, synthetic or redacted values only) enters the repo.

## Steps

Claude runs every `run.sh` line; **Mark** steps are marked.

1. `muse --version` (pin it in RESULT.md). If Muse Code is missing, install it from Meta's
   instructions at dev.meta.ai. **Mark:** in Muse's settings, Contributor mode is off.
2. `run.sh setup`, then `run.sh test` (must pass).
3. Offline reading, no network: `muse --help`, `muse login --help`, `muse serve --help` and the
   config reference, for the cloud, remote, telemetry and auto-update switches (D-138), any
   base-URL override, and a status, usage or whoami command.
4. Sign-in: `run.sh rec signin`, then `run.sh muse login`. **Mark:** open the printed link on the
   phone, enter the code, approve.
5. Reads and one blocked turn: `run.sh rec reads`, then the status/usage command from step 3 and
   one non-interactive turn (`run.sh muse exec "Reply ok. $(run.sh canary)"` or the CLI's
   equivalent; every prompt in every step ends with the canary). The recorder
   refuses the model call (503), so its request body shape is logged and nothing is spent.
   **Check before step 6:** `run.sh scan` must report at least one blocked model call, and the
   CLI must not have printed a model reply. If either fails, the detector missed the turn's shape
   (for example a gRPC or protobuf body): stop and report; do not go on to step 6.
6. Contributor mode read. **Mark:** turn Contributor mode on. `run.sh rec contrib-on`, repeat
   step 5 (the model call is still refused, so no prompt reaches Meta). **Mark:** turn it off.
   `run.sh rec contrib-off`, repeat step 5. After each repeat, the step-5 check again:
   `run.sh scan` shows at least one blocked model call in that phase and no reply was printed;
   otherwise stop, and turn Contributor mode off first if it is on.
7. Optional, only on Mark's yes in the thread: `run.sh rec turn 1` and one `Reply ok.` turn, for
   quota headers and the reply stream's shape (one small turn, Contributor mode off; any second
   request carrying the canary, such as a telemetry copy of the prompt, is still refused).
8. Refused login: `run.sh rec refused`, `run.sh muse logout`, repeat step 5's turn.
9. `run.sh scan` must end `scan: clean`; send its host table and `log.jsonl` back to the thread,
   then `run.sh clean all`. The thread writes `RESULT.md` here.

**Stop and report** (do not work around) if: step 5's or a step-6 check fails (a CLI that
ignores the proxy variables goes direct, so step 5 can spend one synthetic turn before its check
stops the run; nothing the recorder does can prevent that); the log shows `tls-refused` records (the CLI ignores
the CA bundle; the fallback is a base-URL override through `run.sh reverse`, and trusting the CA
system-wide is Mark's call); the CLI keeps its login in the macOS Keychain rather than the
isolated HOME (logout in step 8 must remove it; say so either way); any brief stop condition
(Contributor mode not readable from any answer, account named nowhere, sign-in not a device code
or code exchange).

## RESULT.md checklist (from the brief)

Each item filled or marked `not observed` with the step tried: hosts, methods and paths for model
calls, reads, refresh and sign-in; one model request body per turn kind (keys, item types); the
token answer's fields and kinds; where the account id is; the refresh body's keys; refused-login
codes; quota or usage headers and windows; how `muse login` prints its link and code; the field
reporting Contributor mode, on and off; the cloud, remote, telemetry and auto-update switches; the
inbound API candidate (muse-code-sdk driving `muse serve`).
