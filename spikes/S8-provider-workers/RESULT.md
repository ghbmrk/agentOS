# S8 result: provider agents as workers (cloud part)

**Answer: mechanically yes for both CLIs; custody splits by provider's terms.**
Claude Code 2.1.289 and Codex CLI 0.160.1 both ran headless with tools on, against stub backends, holding only placeholder logins, and their tool calls executed. Broker-side injection of the real login works mechanically for both. Anthropic's published terms, read literally, forbid the broker holding a Claude login; OpenAI's documentation supports ChatGPT sign-in on trusted private runners. So the draft spec diff ([SPEC-DIFF.md](SPEC-DIFF.md)) keeps two custody modes and lets each provider's terms pick.

Everything below is measured against stubs (`stub_anthropic.py`, `stub_codex.py`), not real accounts. Rows marked *live* need Mark's accounts (end of file).

## 1. Headless with tools on

| | Claude Code | Codex CLI |
|---|---|---|
| Command | `claude -p "<brief>" --output-format stream-json --verbose --allowedTools Bash --max-turns 4` | `codex exec --json --sandbox workspace-write "<brief>"` |
| Tool ran | yes: stub answered `tool_use Bash`, the CLI ran it, sent the `tool_result` back (`results/claude_stub.jsonl`) | yes: stub answered `function_call exec_command`, the CLI ran it, sent the output back (`results/codex_stub_provider.jsonl`) |
| Tools offered by the CLI | 22 tools in the request (Bash, Edit, Read, Write, WebFetch, WebSearch, Task, ...) | none listed in the request against the stub, because the stub serves no model catalog; `exec_command` still ran. *Live:* the real tool list |
| Exit on finish | 0, with a `result` line carrying usage and cost-equivalent | 0, with `turn.completed` carrying usage |

Inside a worker machine the worker is already the sandbox (ARC-5, CAP-8), so Codex's own sandbox can be `danger-full-access` there. *Live:* check Codex's Landlock/bubblewrap sandbox under gVisor, if we keep it as a second layer.

## 2. Login held by the broker, placeholder in the sandbox

**Claude Code.** `CLAUDE_CODE_OAUTH_TOKEN=<placeholder>` plus `ANTHROPIC_BASE_URL=http://<broker>/...` sends every model call to the base URL with `Authorization: Bearer <placeholder>`, over plain HTTP, so the broker's existing egress shape (guest path `/<adapter>/...`, broker speaks HTTPS upstream, egress E1) fits without terminating TLS. The token from `claude setup-token` is valid for a year and needs no refresh.
- Without `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` the CLI also opened 6 direct tunnels to `api.anthropic.com:443`, bypassing the base URL (`results/claude_stub.jsonl`). With it set, the only traffic was the 2 model calls (`results/claude_stub_nonessential_off.jsonl`). The broker should still deny any direct tunnel.

**Codex CLI.** `auth.json` held a placeholder access token, refresh token, and an unsigned synthetic `id_token`; the CLI did not verify the JWT. Every backend call carried `Authorization: Bearer <placeholder>` and `chatgpt-account-id`.
- With only `chatgpt_base_url` overridden, most calls went to the base URL, but the run failed: "workspace routing discovery" insists on an HTTPS origin, and some calls (`ab.chatgpt.com`, `chatgpt.com`) went direct (`results/codex_stub.jsonl`).
- A model provider with `requires_openai_auth = true` and a `base_url` ([codex_provider.toml](codex_provider.toml)) keeps ChatGPT sign-in and sends the Responses call to the broker. The run then completed. Codex still made ~20 side calls (plugin lists, `wham/accounts/check`, `wham/settings/user`, analytics, an MCP endpoint), all carrying the placeholder; the broker should declare only `POST .../responses` (and the models list) and deny the rest (ADP-10).
- **Refresh.** Codex refreshes ChatGPT tokens itself through `auth.openai.com/oauth/token`, and OpenAI's CI guidance is to let Codex refresh and persist `auth.json`. With a placeholder refresh token that request must also pass through the broker, which substitutes the real refresh token and swaps the new real tokens in the response back to placeholders. Not tested here (needs TLS termination for `auth.openai.com`; Codex honours `CODEX_CA_CERTIFICATE`). *Live:* the refresh cadence and whether the swap holds.

**Terms (read 2026-10-05; inference where marked).**
- Anthropic, [Claude Code legal and compliance](https://code.claude.com/docs/en/legal-and-compliance), read from the live page (its Markdown source) on 2026-10-05 ~22:00Z, quoted verbatim: "developers may not collect, store, or intermediate Claude.ai credentials or session tokens — sign-in to a Claude account must complete through Anthropic's own flow". The same page allows "an end user signing in to the unmodified Claude Code binary with their own Claude subscription, including where a platform hosts Claude Code", and says running Claude Code in "products or services (e.g. in hosted sandboxes or other agent infrastructure)" requires the Commercial Terms. A broker that holds the owner's Claude token and injects it is, on a literal reading, storing and intermediating it. **So broker-held custody is ruled out for Claude** (inference from the text; only Anthropic can say otherwise). `claude setup-token` is documented for "CI pipelines and scripts", so scripted, headless use of one's own plan through the unmodified CLI is explicitly supported.
- OpenAI, **unverified**: the Codex docs (search summaries only, 2026-10-05; the pages are blocked by this session's egress) recommend API keys for automation but document ChatGPT-managed auth for "trusted private infrastructure" that persists the refreshed `auth.json`, with access tokens "intended for trusted scripts, schedulers, and private CI runners". Nothing found on a proxy holding the tokens. **Not settled**: broker-held custody for Codex stays unverified until someone reads OpenAI's terms directly; the live part should do that.

**Consequence: two custody modes** (SPEC-DIFF CRED-5):
- **Broker-held (B):** the real login stays in the vault process; the worker holds placeholders; injection at egress. CRED-1 holds unchanged. Allowed only where the provider's terms permit a proxy to hold the login. Candidate: Codex, pending the terms read.
- **Worker-held (W):** the owner signs in through the provider's own flow inside the worker; the CLI keeps its own credential on a per-provider login volume that only that provider's workers mount, excluded from snapshots, recall, journal, and logs. Egress for the worker is a CONNECT-only allowlist of the provider's model hosts (no TLS termination, so the broker never sees the token). This is a scoped exception to CRED-1: the CLI is model-directed and can read its own login. Its blast radius is that one plan's model quota (a setup token "can only make model requests"), and results leaving the worker are scanned for the provider's token formats (`sk-ant-oat01-` and the like) before the guest sees them. Candidate: Claude.

## 3. Quota and rate-limit windows

| | Claude Code | Codex CLI |
|---|---|---|
| On the wire (broker can read) | Response headers `anthropic-ratelimit-unified-{5h,7d}-{utilization,reset}`, `-status` (`allowed`, `allowed_warning`, `rejected`), `-representative-claim` (`five_hour`, `seven_day`), `-reset`, `-*-surpassed-threshold`, overage headers (about 30 names in the binary) | Response headers `x-codex-{primary,secondary}-{used-percent,window-minutes,reset-at}`; primary is 300 min, secondary 10080 min |
| From the CLI | stream-json `rate_limit_event` with `status`, `rateLimitType`, `utilization`, `resetsAt`, and both windows (`results/claude_stream.jsonl`) | `token_count` events with `rate_limits.{primary,secondary}` in the session rollout file, not in `exec --json` (`results/codex_rollout.jsonl`) |
| Usage per run | `result.usage` and `modelUsage` (tokens, cost-equivalent USD) | `turn.completed.usage` (tokens) |
| Window used up | stub 429 + `status: rejected`: the CLI exits 1 within 1 s with a `rate_limit_event` (`results/claude_stream_exhausted.jsonl`) | stub 429 `usage_limit_reached`: the CLI exits 1 within 1 s, "You've hit your usage limit ... try again at <time>" (`results/codex_stream_exhausted.jsonl`) |

Neither CLI waits out a window, so failover to the next route is the broker's job and costs about a second.

In mode B the broker reads the headers on its own connection, as OP-8 already prefers. In mode W the tunnel is opaque, so quota comes from the CLI's own events, which are guest-reported. That is acceptable for **routing** only: the provider enforces the plan's cap itself and a flat-rate plan has no spend to protect, so a lying worker can only misroute its own provider. It never feeds OP-8 spend.

*Live:* real header values, how `allowed_warning` thresholds map to utilization, the weekly model-specific windows (`seven_day_opus`, `seven_day_sonnet` appear in the Claude binary), and whether Codex's `credits` fields matter for Plus.

## 4. Capping a run

The broker can cap a provider-agent run at four points, outermost first:
1. **Worker machine:** wall clock, CPU, memory, and process cap (RES-2, CAP-8); on expiry the machine is stopped and the run is reported as cut off.
2. **Egress (mode B):** count calls and tokens per run from the stream (the broker already parses Anthropic SSE usage, route R14), and answer the next call with a broker-marked 429 (`egress.DeniedHeader`). Both CLIs exit at once on a 429 (measured above). In mode W the broker can only close the tunnel.
3. **CLI flags:** Claude `--max-turns`, `--max-budget-usd` (API-priced cost-equivalent, which works as a size cap even on a plan), `--disallowedTools`; Codex `-c` overrides and `--sandbox`. These are the CLI honouring its own limit, so they are a convenience, not enforcement.
4. **Quota admission:** before starting a run, refuse it when the plan's window is past the owner's reserve (SPEC-DIFF RES-5), so the box never eats the share of the plan the owner keeps for their own use.

A run is metered as runs and quota, not tokens: the broker cannot route model calls inside a provider's run (CAP-9 applies per run, not per call).

## Can the agent read its own login? (Security W1)

Security accepted worker-held custody only if the agent's tools cannot read the login (W1). Measured with Claude Code and `CLAUDE_CODE_OAUTH_TOKEN` holding a placeholder, tools allowed (`IS_SANDBOX=1`, `--permission-mode bypassPermissions`, as inside a worker):
- The Bash tool's own environment does **not** carry the token: Claude Code strips it from tool subprocesses.
- But a tool can read it from the parent CLI's `/proc/<pid>/environ` (same user): found in 2 of the CLI's processes (`results/claude_stub_env_probe.jsonl`).
- Claude Code's built-in sandbox (bubblewrap) might hide `/proc`, but bubblewrap is not installed in this session, and enabling the setting changed nothing here (`results/claude_stub_env_probe_sandboxed.jsonl`).

So **W1 is not met by default**. Candidate fixes for the image: tools under a separate user or PID namespace (the CLI's sandbox with bubblewrap, or `hidepid=2` on `/proc` with tools as another user), plus managed-policy deny rules on the credential path. *Live/qualification:* prove one of these with the canary-encoding brief. Under the default auto permission mode the CLI's classifier declined the probe command, but that is not a boundary.

## Usage pools (Mark's addition)

Mark asked for separate pools per product (Codex vs ChatGPT) and for the route type to stay open to other frontier tools (Grok, Gemini). What the CLIs show:
- Codex tags its quota with `limit_id: "codex"` (`results/codex_rollout.jsonl`), which suggests the backend meters per product, so Codex is its own pool beside ChatGPT chat. *Live:* confirm with a Plus plan that ChatGPT chat use does not move the Codex percentages.
- Claude Code's binary knows pools beyond the 5-hour and 7-day windows: `seven_day_opus`, `seven_day_sonnet`, `seven_day_oauth_apps`, `seven_day_cowork`. So one plan can carry several pools, some per model.
- Nothing in either CLI's interface is provider-specific beyond the declaration fields in SPEC-DIFF CAP-11 (command, custody, hosts, pools and where they are read, the used-up signal). Gemini CLI and a Grok CLI would plug in through such a declaration once their terms are read; Google ended plan access for open-source agents on 2026-06-18 (from the Q&A thread), so Gemini needs that read first.

## Coordination and onboarding (Mark's additions)

- **Guest coordination.** Routing alone hides the resources from the guest, so it cannot plan "Codex writes, Claude reviews, both in parallel". SPEC-DIFF adds CAP-12: a broker `resources` tool showing each route's qualified task classes, pool headroom and reset, marginal cost, free concurrency and label permission, with no credential detail; route preferences the broker honours within grants and reserves; and results passed between workers as worker artifacts through broker tools. Pools are general across providers, declared per provider agent (RES-5).
- **Onboarding.** Step 6 gains **Use my plan** beside **Use an API key**, the provider's own sign-in flow (needed for Claude's terms anyway), and two defaulted questions per plan: private data (no) and the reserve (30%). The local page shows one line per pool; failover is told in the digest with its cost, and only a foreground wait is texted. Codex has a device-code login (`codex login --device-auth`) that fits the phone flow; Claude's `setup-token` is a browser flow whose link the page can show. *Live:* both flows on a phone.

## Surprises

- Codex has a built-in "credential broker" and managed network proxy config (`network_proxy`, `credential_broker` in the binary). Not explored; it might give a supported placeholder path. *Live:* check its documentation.
- Claude Code honours `ANTHROPIC_BASE_URL` with a subscription token, which is what makes mode B mechanically trivial, and also why the terms, not the mechanics, decide it.

## Needs Mark (live part)

1. **Claude:** a Pro or Max plan; run `claude setup-token` in a browser once (mode W: inside a worker on the box's local page, once that exists; for the spike, on any machine) and run the same brief against the real API. Record the real rate-limit headers and `rate_limit_event`s through one 5-hour window. Decide whether to ask Anthropic (their [contact page](https://www.anthropic.com/contact-sales) is the route the docs give) whether a self-hosted owner box counts as "a platform hosting Claude Code"; only Mark can make that contact.
2. **Codex:** a ChatGPT Plus or Pro plan; `codex login --device-auth` once; run the same brief with the real backend. Record the `x-codex-*` headers, how often Codex refreshes, and whether the broker-side refresh swap works. Read the current OpenAI terms on proxies holding ChatGPT-managed tokens (this session's egress blocks openai.com).
3. Network: a custom network policy allowing `api.anthropic.com`, `chatgpt.com`, `auth.openai.com` for the live session.

## Files

- `run_claude_stub.sh`, `stub_anthropic.py`: Claude Code runs (`STUB_MODE=exhausted` for the 429 case, `EXTRA_ENV` for env toggles).
- `run_codex_stub.sh`, `stub_codex.py`, `fake_codex_auth.py`, `codex_provider.toml`: Codex runs (`EXTRA_TOML="$(cat codex_provider.toml)"` for the completing run).
- `results/`: request logs (auth header classified as placeholder or not, never the value), CLI streams.

Model usage: one session at about 1-2% of the weekly limit (estimate).
