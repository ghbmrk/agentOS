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
