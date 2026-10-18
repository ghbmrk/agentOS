# Codex credential shapes from a supervised login (#2313)

The Codex declaration's `CredFormats` (broker/provagent/declare.go; ASSUMPTIONS CAP-11-plan-fu4-P17) are the
public token shapes, not measured. This procedure records the shapes of the tokens a real
sign-in leaves in the pinned CLI's `auth.json`: prefix, character classes, length and dot
segments, and whether each declared format matches. No token value is ever printed, logged,
committed or pasted into chat.

## Host

The builder host of RESULTS.md: a Linux x86_64 cloud session (root, no KVM needed) with
- runsc release-20260928.0, CI's checksum-pinned install (`.github/workflows/ci.yml`, "Install
  gVisor"), including `/usr/local/bin/gvisor-bin/`;
- Go (`GOTOOLCHAIN=go1.26.8`), python3 with `requests`, jq, curl, openssl;
- egress to `auth.openai.com` in the environment's network policy. That is the only OpenAI host
  the sign-in uses; `chatgpt.com` is not needed because no model or usage call is made.

Not the Mac Studio or the M6: runsc needs Linux.

## Run

1. Agent: `GOTOOLCHAIN=go1.26.8 spikes/S8-live/run.sh setup` (builds the pinned Codex rootfs, the
   relay and `shapes/`, after its tests pass).
2. Agent: `spikes/S8-live/run.sh shapes`. Inside a gVisor machine with no network but loopback,
   the CLI runs `codex login --device-auth` against the forwarder (`fwd.py`, relay mode), which
   relays to `auth.openai.com` and swaps the `redirect_uri` (RESULTS.md, #809).
3. Owner, at the keyboard: open `https://auth.openai.com/codex/device`, sign in to the ChatGPT
   plan and enter the code the agent relays. The code is a one-time sign-in code, not a token.
4. Inside the machine, `shapes/` reads `/var/lib/agentos-codex/auth.json` and prints only the
   shape fields to the machine's stdout, between `== shapes begin` and `== shapes end`; the CLI
   then logs out and `auth.json` is removed. `runsc do`'s memory overlay also covers the volumes,
   so nothing written inside reaches the host: the login is gone when the machine exits.
5. Agent: `run.sh` prints the forwarder log (method, path, status only), cuts the lines between
   the markers into `$W/shapes.json` and prints it.
   Then `run.sh clean`.

## What leaves the machine

`shapes/` (`main.go`, tested by `main_test.go` with synthetic canaries) prints, for each string
in `auth.json`, only:
- its length, and its prefix when it is a public one (`sk-…`, `eyJ`, `rt_`) or two to four
  lowercase letters and `_` or `-` (the vendor-prefix form; reported as generic);
- its character classes (`A-Z`, `a-z`, `0-9` and each punctuation character);
- the lengths of its dot segments; for a JWT, `alg` and `typ` from an allowlist and the header
  and claim names (never claim values, so no email or account id);
- for each Codex `CredFormats` pattern: `full`, `partial` or `none`.

`auth_mode` prints its value only when it is `chatgpt` or `apikey`; `last_refresh` prints
present; strings under 16 bytes print their length only. `TestOutputHoldsNoValue` checks that no
6-byte window of a value appears in the output; `TestFormatsMatchDeclaration` checks the patterns
are the declaration's verbatim.

## Where the result goes

- RESULTS.md, a "Credential shapes (#2313)" section: the shapes as printed, the CLI version and
  the date.
- #2313: the same shapes as a comment.
- Then a follow-up PR confirms or corrects the Codex `CredFormats` in broker/provagent/declare.go
  and ASSUMPTIONS CAP-11-plan-fu4-P17 (tier A: broker/).

## Assumptions

- The pinned CLI (0.162.1) stores the login in `$CODEX_HOME/auth.json` when no keyring is
  reachable, as in the machine. If it does not, `shapes` exits "no auth file" and nothing else
  is printed.
- The tokens of one sign-in stand for the shapes the CLI receives; a refresh issues tokens in the
  same shapes. A refresh is not exercised here.
- The API-key field is set only when the sign-in issues one; if it is null, the `sk-` shape stays
  the public one.
