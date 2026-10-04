# S4 inventory: every way OpenClaw 2026.9.8 acts on the world

Source: openclaw/openclaw @ `fc23bc8` (tag v2026.9.8). Paths are relative to that tree.
Tags: **[V]** verified in source/schema, **[D]** from docs, **[I]** inferred. Runtime-confirmed items are marked **[R]** (see RESULT.md).

**Framing.** Inside an agent machine the guest has root and `exec` (spec REV-1). It can rewrite its own config, install plugins, or open sockets. So every config switch below is defense in depth. The boundary that matters is the agent machine's network: default-deny except broker sockets (spec §4). Config tamper friction: read-only config mount, `OPENCLAW_CONFIG_READONLY=1` (src/config/config-write-guard.ts:9-21) [V], `gateway.reload.mode:"off"` (src/config/zod-schema.gateway.ts:391) [V].

## 1. Built-in tools (catalog: src/agents/tool-catalog.ts:70-520) [V]

External-effect tools, all deniable by `tools.deny` (deny wins over allow; groups in docs/gateway/config-tools/tool-policy.md:65-79):

| Tool | Effect | Ref |
|---|---|---|
| `message`, `conversations_send`, `conversations_turn` | send on chat channels | tool-catalog.ts:358, :219-232 |
| `code_execution` | runs Python on a remote provider (xAI) | :121 |
| `secrets` | asks the human for credentials, stores them in the guest | :128; src/agents/tools/secrets-tool.ts:35 |
| `github_publish` | opens draft PRs | :254 |
| `browser`, `portal`, `nodes`, `computer`, `mobile_ui` | browser / exposed apps / paired devices | :303, :338, :400-414 |
| image/music/video generate, `tts` | paid provider APIs | — |
| `automations` (cron) | scheduled jobs incl. webhook delivery | root-shape.ts:383-416 |
| `gateway` | `config.get`, `update.run` | src/agents/tools/gateway-tool.ts:109 |
| `plugins` | install from catalog / ClawHub | plugins-tool.ts:84-98 |
| `openclaw` | delegates config, plugin, provider and API-key changes to a second model turn | openclaw-delegate-tool.ts:92-97 |

Policy keys: `tools.profile`, `tools.allow|alsoAllow|deny`, `tools.byProvider`, `tools.elevated`, `tools.exec.{host,security,ask}`, `tools.web.{search,fetch}.enabled`; per agent under `agents.entries.<id>.tools` (zod-schema.agent-runtime.ts:137-146, 302, 604-612, 735-812) [V].
Verdict: every built-in can be **disabled** by config; none can be **redirected** to the broker. Deny them and offer broker tools instead.

## 2. Ways to add tools
- **Native MCP client** [V][R]: `mcp.servers.<name>.{url, transport:"streamable-http"|"sse", command/args (stdio), headers, toolFilter, auth, ...}` (src/config/zod-schema.mcp-server.ts:15-73). Tools appear as `<server>__<tool>` under plugin id `bundle-mcp`. Avoid `auth:"oauth"`: it stores tokens in `state/openclaw.sqlite`.
- **Plugins** [V]: `api.registerTool({name, description, parameters, execute})`, manifest `openclaw.plugin.json` `contracts.tools`, loaded via `plugins.load.paths`; a plain `{id, register}` default export works without the SDK (src/plugins/module-export.ts:28-37). Workspace-dropped plugins are disabled unless allowlisted (config-activation-shared.ts:188-194).
- **Skills**: prompt files + scripts run through `exec`. No new privilege.
- **HTTP** `POST /tools/invoke` on the gateway, behind gateway auth [D].

## 3. Model access [V][R]
`models.providers.<id>.{baseUrl, apiKey, api, headers, request{...,allowPrivateNetwork}, models[]}` (zod-schema.core.ts:552-612). `api` ∈ openai-completions, openai-responses, anthropic-messages, google-*, ollama, bedrock, … A literal placeholder `apiKey` is accepted. Select with `agents.defaults.model.primary: "<provider>/<model>"`.
Credential stores inside the guest, which must stay empty: `agents/<id>/agent/openclaw-agent.sqlite` (auth profiles), `state/openclaw.sqlite` (shared auth, MCP OAuth), legacy `credentials/oauth.json`, `auth-profiles.json` (docs/gateway/security/secrets-and-storage.md:27-50). OAuth providers keep and refresh tokens in the guest (docs/concepts/oauth.md:51-78), so never run `openclaw onboard` with real logins inside a guest.

## 4. Owner messages in, replies out (no channel plugin needed)
- `openclaw agent --local --message ...` (CLI, one turn) [R].
- Gateway `POST /v1/chat/completions` with `gateway.http.endpoints.chatCompletions.enabled` (zod-schema.gateway.ts:415-425), `model:"openclaw"`, stable `user` per owner thread, bearer gateway token [V/D]. Best fit for a broker-driven inbound path.
- WebSocket RPC `chat.send` / `sessions.*`; `/hooks/agent` (needs `hooks.enabled`) [D].
- Agent-initiated messages to the owner (cron, heartbeat): a broker tool (`owner_notify`), not a channel plugin [I].
- Owner text may be parsed as slash commands: `commands.{config,mcp,plugins,bash,restart}:false` (zod-schema.session.ts:9-22) [V].

## 5. Direct network clients outside the tool path

| Client | Off switch | Ref |
|---|---|---|
| Update check + telemetry | `update.checkOnStart:false`, `OPENCLAW_NO_AUTO_UPDATE=1`; `telemetry.enabled` (default off), `DO_NOT_TRACK` | src/infra/update-startup.ts:307-308; telemetry.ts:107-108 |
| Auto-update | `update.auto.enabled` (default false), `nodeHost.autoUpdate.enabled` | node-host/auto-update.ts:36 |
| Model catalog (catalog.openclaw.ai) | `models.catalogRefresh.enabled:false` | model-catalog/remote-config.ts:3-11 |
| ClawHub | on demand only [I]; `OPENCLAW_CLAWHUB_URL` redirects | infra/clawhub-client.ts:19,78 |
| mDNS/Bonjour | `discovery.mdns.mode:"off"` (default minimal), `OPENCLAW_DISABLE_BONJOUR=1` | gateway/server-discovery-runtime.ts:51,119 |
| Tailscale CLI | `gateway.tailscale.mode:"off"` | zod-schema.gateway.ts:377 |
| Cron webhooks | `cron.enabled:false` or deny `automations` | root-shape.ts:383-396 |

Proxy: honors `HTTP(S)_PROXY` (src/infra/net/undici-global-dispatcher.ts:196-221) and `proxy.proxyUrl` / `OPENCLAW_PROXY_URL` process-wide incl. node:http and WebSocket (docs/security/network-proxy.md) [V]. Loopback bypasses the proxy by default.

## 6. Self-modification
`plugins` (install/enable), `openclaw` (config, providers, keys), `gateway update.run`, `skill_workshop` + `skills.workshop.autonomous.mode` (off/propose/auto), skill files written into the workspace, and `openclaw config set` / `openclaw update` through `exec`. Countermeasures: deny the tools, read-only config, `reload.mode:"off"`. Inside a rebuildable agent machine (ARC-4) these only damage that machine.

## 7. Subprocesses it starts itself
MCP stdio servers; `models.providers.*.localService`; CLI media models; login-shell env import (`env.shellEnv.enabled`); Chrome (`browser.enabled`); ACP coding CLIs (`acp.enabled`); git/gh, tailscale, update/respawn helpers, SQLite workers.

## 8. Its own sandboxing
`agents.defaults.sandbox.mode` off|non-main|all (default off), backends docker/podman/ssh/… Irrelevant when OpenClaw is itself the guest: keep `off`, `tools.elevated.enabled:false`. When on, `tools.sandbox.tools` adds a second gate that hides MCP/plugin tools.
