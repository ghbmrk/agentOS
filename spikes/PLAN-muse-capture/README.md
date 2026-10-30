# PLAN-muse-capture: supervised Muse Code capture (#1379 slice (b))

Measures Muse Code's traffic on Mark's own Muse plan so slice (c) can write `plan.Muse` from
measurements (brief: `briefs/PLAN-muse.md` slice (b), PR #3922). It follows S8-live (#809): a
proxy sits between the CLI and Meta, the log holds shapes only, no model usage is spent, and the
login is kept apart and removed afterwards. Mark's go-ahead: "Yes, Muse then Grok" on the
supervised-capture card (cmsg_01R91wiieBzMSvPKFsAJVvuKVNhu2hta1WiGwNjGyPyMPW).

**Where it runs.** On Mark's Mac through Remote Control. The cloud environment's network policy
refuses Meta's hosts, and the host list is what this capture measures. Nothing here needs admin
rights or changes system trust. `run.sh` works on Linux too.

## The gate

`record.py` refuses by default. It is a gate, not a filter: nothing reaches Meta unless it is on
a list, so a prompt cannot slip past it through an encoding the gate failed to recognise.

- **No-prompt phases** (sign-in, reads, the Contributor-mode reads, refused login). An HTTP request
  passes only when all of these hold:
  - its `METHOD host normalised-path` is a line of `$W/allow.txt`;
  - its body is empty, or JSON or a form, decoded strictly;
  - it has no model key (`messages`, `message`, `input`, `prompt`, `contents`) at any depth.

  The gate adds each passed request's exact URL to `$W/seen.txt`. It refuses everything else
  with 503 before it leaves.
- **The one prompt phase** (step 7, `rec turn strict`, Contributor mode off). Only a GET or HEAD
  request passes, with no body and with an exact URL from `seen.txt`. Each such URL was sent
  before any prompt existed. Nothing built from the prompt can leave in a URL or a body. The
  channels the gate does not compare are header values, chunked or HTTP/2 trailers (if a client
  sends them), and the `CONNECT` target hostname and SNI, which are resolved and connected
  upstream before a non-HTTP flow is killed.
- **Allow lines name the real destination.** The host in an allow line is the connection's
  destination (`host`, or `host:port` off the default port). A request whose `Host` header names
  a different host is refused.
- **Every non-HTTP flow is killed and its bytes are emptied.** That covers raw TCP after
  `CONNECT`, UDP and websockets. An error inside a hook refuses the request.

**What may go on the allow list.** Claude reviews `run.sh refused` and adds lines with `run.sh
allow`, only in no-prompt phases and never in step 7. Only these may be added:
- sign-in, device-code, token and revoke endpoints;
- account, profile and whoami reads;
- settings reads;
- usage and quota reads.

These are never added:
- telemetry, logging, events, analytics, crash reports and feedback;
- uploads and auto-update;
- any model, chat, turn, completion or generate endpoint;
- any shared endpoint (such as `/graphql`) whose refused bodies carry free-text fields.

The CLI runs in an empty working directory, so it has no files to upload.

**What is kept, and where.** The run keeps three things under `$TMPDIR/agentos-muse-capture`, a
directory with mode 700:
- `log.jsonl`, the shapes-only log. It holds hosts, methods, paths with ids replaced by `{id}`,
  statuses, header names, quota-like header values, and body key names and kinds. It never holds
  a token, cookie, prompt, reply, email or account id. `record_test.py` checks this with
  synthetic canaries, and `run.sh scan` re-checks the real log.
- `allow.txt` and `seen.txt`, the lists the gate passes against. They stay local.
- `home/`, the CLI's login. `run.sh clean` logs it out and deletes it.

Only `RESULT.md` enters the repo. It is written from the scanned log, with synthetic or redacted
values only.

## Steps

Claude runs every `run.sh` line. Steps marked **Mark** are his to do.

1. Run `muse --version` and pin the version in RESULT.md. If Muse Code is missing, install it
   from Meta's instructions at dev.meta.ai. **Mark:** check that Contributor mode is off in
   Muse's settings.
2. Run `run.sh setup`, then `run.sh test`. The tests must pass.
3. Read offline, with no network: `muse --help`, `muse login --help`, `muse serve --help` and
   the config reference. Look for the cloud, remote, telemetry and auto-update switches (D-138),
   any base-URL override, and a status, usage or whoami command.
4. **Sign-in.** Run `run.sh rec signin`, then `run.sh muse login`. If it fails, check `run.sh
   refused`, allow only the sign-in endpoints, and retry. **Mark:** when the link and code show,
   open the link on the phone, enter the code and approve.
5. **Reads.** Run `run.sh rec reads`, then the status, usage and whoami commands from step 3.
   Allow account, settings and usage reads as they appear, then repeat the commands until they
   run.
6. **Contributor mode, read with no prompt.** No prompt is sent in this step.
   - **Mark:** turn Contributor mode on.
   - Run `run.sh rec contrib-on` and repeat step 5's commands.
   - **Mark:** turn Contributor mode off.
   - Run `run.sh rec contrib-off` and repeat step 5's commands.
7. **One refused turn**, with Contributor mode off (confirmed in step 6). Run `run.sh rec turn
   strict`, then one non-interactive turn: `run.sh muse exec "Reply ok."` or the CLI's
   equivalent. The gate refuses the model request, and the log keeps its body shape.
   **Check:** the log holds a refused POST in phase `turn`, and the CLI printed no model reply.
   If either check fails, stop.
8. **Refused login.** Run `run.sh rec refused`, then `run.sh muse logout`. Allow the revoke
   endpoint if it was refused, and retry the logout. Then repeat one of step 5's reads.
9. Run `run.sh scan`. It must end with `scan: clean`. Send its counts and `log.jsonl` back to the
   thread, then run `run.sh clean all`. The thread writes `RESULT.md` here.

**Stop and report**, and do not work around it, if any of these happens:
- step 7's check fails;
- the log shows `tls-refused` records, meaning the CLI ignores the CA bundle (trusting the CA
  system-wide is Mark's call);
- a needed endpoint is one that may not be allowed;
- the CLI keeps its login in the macOS Keychain rather than the isolated HOME (step 8's logout
  must remove it; report this either way);
- traffic bypasses the proxy. A CLI that ignores the proxy variables goes direct and the gate
  cannot see it. The sign-in would then fail through the gate or show no records;
- any of the brief's stop conditions holds: Contributor mode cannot be read from any answer, the
  account is named nowhere, or the sign-in is not a device code or code exchange.

## RESULT.md checklist (from the brief)

Fill each item, or mark it `not observed` with the step tried:
- the hosts, methods and paths used for model calls, reads, refresh and sign-in;
- one model request body per turn kind (keys and item types, from step 7's refused record);
- the token answer's fields and kinds;
- where the account id is;
- the refresh body's keys;
- the refused-login codes;
- quota or usage headers and their windows;
- how `muse login` prints its link and code;
- the field that reports Contributor mode, with it on and off;
- the cloud, remote, telemetry and auto-update switches;
- the inbound API candidate (muse-code-sdk driving `muse serve`).
