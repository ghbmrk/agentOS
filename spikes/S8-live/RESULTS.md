# S8-live results: ChatGPT plan, host mode (#809)

Run 2026-10-16 ~16:45Z on the builder host with Codex CLI 0.162.1 (the pinned
`CODEX_VERSION` in guest/codex/build-rootfs.sh), signed in with Mark's ChatGPT
plan by device code (approved on the #809 card; terms per D-117). The CLI's
traffic went through `fwd.py` (relay mode) and `relay/`; `fwd.py` blocked every
`/responses` call, so no model call, plan usage or credit was spent. Logs hold
paths, statuses, x-codex headers, tool types and key names only; no token or
Bearer string appears in them. The login was logged out and its CODEX_HOME
deleted after the run.

## Credits (GET /backend-api/wham/usage, 200)

- weekly window (604800 s) at used_percent 100, `limit_reached: true`,
  `allowed: false`; no secondary window.
- credits: `has_credits: true`, `unlimited: false`,
  `overage_limit_reached: false`; spend_control not reached. The plan type and
  credit balance are left out on purpose: they describe the account, not the
  CLI's behaviour.
- So this is the credits-after-limit state: the weekly limit is reached and
  credits are available to continue. Other keys present: `model_usage`,
  `rate_limit_reached_type`, `rate_limit_reset_credits`.

## Managed config off

The host has no /etc/codex, so no managed layer applied; the provider was
pointed at the forwarder with `-c model_providers.*` overrides. The blocked
POST /backend-api/codex/responses carried, for both the default config and
`web_search="live"`:

- no top-level `tools`; one developer-role `additional_tools` item whose tool
  types are only `namespace`, `function` and `custom` (namespaces functions,
  clock, collaboration);
- no hosted tool type (no web_search), identical to the managed-config-on run.

Whether the absence of a hosted search tool with `web_search="live"` comes from
the server's model capability list or from the client is inferred, not
verified. A further run routing `chatgpt_base_url` through the forwarder was
refused by the CLI ("workspace backend must use an HTTPS origin without
credentials") before any /responses request.

## Credential shapes (#2313)

Run 2026-10-18 13:38Z on the builder host (runsc release-20260928.0) with Codex
CLI 0.162.1, by `run.sh shapes` (SHAPES.md): Mark's device-code sign-in to his
ChatGPT plan through `fwd.py` in relay mode, no model call. The forwarder log
shows only `deviceauth/usercode`, `deviceauth/token` (403 while pending, then
200), `/oauth/token` 200 and `/oauth/revoke` 200 at logout. The machine printed
only shapes; the login was revoked and `run.sh clean` removed the work directory.

Declared Codex formats (`broker/provagent/declare.go`): F0 `sk-…` API key,
F1 JWT `eyJ….eyJ….…`, F2 `rt_…` refresh token.

| `auth.json` field | Shape | F0 | F1 | F2 |
|---|---|---|---|---|
| `auth_mode` | `chatgpt` | | | |
| `OPENAI_API_KEY` | null (no API key issued) | | | |
| `last_refresh` | present | | | |
| `tokens.access_token` | len 1794, prefix `eyJ`, `A-Z a-z 0-9 - . _`, segments 106.1344.342; JWT RS256, header `alg kid typ`; claims `aud client_id exp https://api.openai.com/auth https://api.openai.com/mfa https://api.openai.com/profile iat iss jti nbf pwd_auth_time scp session_id sl sub` | none | full | none |
| `tokens.id_token` | len 1976, prefix `eyJ`, segments 106.1526.342; JWT RS256 (signed), header `alg kid typ`; claims `acr amr at_hash aud auth_provider auth_time email email_verified exp https://api.openai.com/auth iat iss jti name rat sid sub` | none | full | none |
| `tokens.refresh_token` | len 196, no public or generic prefix, `A-Z a-z 0-9 . _`, segments 2.1.191 | none | none | **none** |
| `tokens.account_id` | len 36, `a-z 0-9 -` (UUID form) | none | none | none |

Findings:
- The access and id tokens are signed JWTs and F1 matches them in full.
- **The refresh token does not match F2.** It has no `rt_` prefix: it is two
  characters, a dot, one character, a dot, then 191 characters of
  `[A-Za-z0-9_]`. No declared format matches it, so the result scan and the
  vault redactor (CAP-11-plan-fu4-P17) miss a Codex refresh token today. The fix to
  `CredFormats` and CAP-11-plan-fu4-P17 is the tier-A follow-up.
- No API key is issued on a plan sign-in, so F0 stays the public shape.
