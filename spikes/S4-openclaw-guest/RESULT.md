# S4 result: OpenClaw runs unmodified as a guest

**Answer: yes.** OpenClaw 2026.9.8 (`fc23bc8`) ran with no network except one loopback stub broker. It used broker-provided model access with a placeholder key, called a broker tool, ran `exec` locally, and took owner messages through its own HTTP API. All of it was set up through its config file. **No source patch was needed, so there is no ARC-3 fork record.**

Two seams need broker-side design rather than a patch: the broker must cap model calls (finding 2), and the broker tool is reached through OpenClaw's tool search, not offered directly (finding 3).

## What ran
Every run used `unshare -n` (only loopback), DNS pointed at a logging NXDOMAIN sink (`dns_sink.py`), `strace` on `connect`/`sendto`/`sendmsg`, and config [`openclaw.json5`](openclaw.json5). The stub broker [`stub_broker.py`](stub_broker.py) serves an OpenAI-compatible endpoint (scripted model; it rejects any key except the placeholder) and an MCP server with one tool, `effect_request`. Its tests are in `tests/test_s4_stub_broker.py`.

| Seam | How it was wired (config only) | Result |
|---|---|---|
| Model access, no credential in guest (CRED-1, CRED-5) | `models.providers.broker` with `baseUrl` = broker, `apiKey` = placeholder, `api: openai-completions` | ✅ Every model call carried only the placeholder. The broker's egress swaps in the real key. |
| Broker tools (spec §9 intents) | `mcp.servers.broker` with `url` and `transport: streamable-http` | ✅ The tool was discovered as `broker__effect_request`. The call reached the broker with the exact arguments. |
| Owner message in, reply out | Gateway `POST /v1/chat/completions` (`gateway.http.endpoints.chatCompletions.enabled`), with a guest-local bearer token | ✅ The reply came back in the HTTP response. No channel plugin was needed. |
| One-shot turn | `openclaw agent --local --message …` | ✅ |
| Work inside the machine (REV-1) | Built-in `exec` | ✅ `uname`, `id` ran. |
| External-effect built-ins | `tools.deny` (web, messaging, ui, nodes, gateway, plugins, openclaw, automations, secrets, code_execution, github_publish, conversations_*, media generation, tts, skill_workshop, …) | ✅ The tool-search catalog went from 54 tools to 25. Direct tools: `apply_patch, edit, exec, ls, process, read, sessions_yield, tool_call, tool_describe, tool_search, write`. |
| Background network (update check, telemetry, model catalog, mDNS, Tailscale) | `update.checkOnStart:false`, `telemetry`, `models.catalogRefresh`, `discovery.mdns.mode:"off"`, `gateway.tailscale.mode:"off"` + env `OPENCLAW_NO_AUTO_UPDATE`, `OPENCLAW_DISABLE_BONJOUR`, `DO_NOT_TRACK` | ✅ In the hardened runs (2 CLI, 5 gateway), every TCP `connect()` went to 127.0.0.1:18080. The only other attempt was one failed DNS lookup in the first gateway run (finding 7). The DNS sink saw no queries in the 4 runs that had it. |

The full side-effect inventory, with source citations, is in [INVENTORY.md](INVENTORY.md).

## Measurements
Cloud VM: 4 vCPU, 15 GB RAM. Node 24.21.0. The model is a stub that answers instantly, so these times are OpenClaw's own overhead.

| Measure | Value |
|---|---|
| Install (`npm install openclaw@2026.9.8`) | 33 s; 343 packages; `node_modules` is 735 MB |
| Runtime requirement | Node ≥ 24.16 (the image's Node 22 is too old) |
| CLI one-shot turn (`agent --local`), 2–3 model calls | 36–40 s wall; peak RSS of the largest process 1.2–1.7 GB |
| Gateway cold start until HTTP is ready | 27.4–28.3 s (5 runs) |
| Gateway turn, 2–3 model calls | 18.8–21.4 s |
| Gateway plus children, RSS after one turn | 1.6 GB (clean run g5) |
| Guest state directory after one turn | 40 MB (SQLite stores, UI asset cache) |

## Findings and surprises
1. **The real boundary is the network, not the config.** The guest is root with `exec` (REV-1), so it can rewrite its own config, install plugins, or call `openclaw update`. The deny list and the off switches only reduce noise and accidents. Containment comes from the agent machine allowing only broker sockets (spec §4), and from ARC-4 rebuilds. Read-only config (`OPENCLAW_CONFIG_READONLY=1`) and `gateway.reload.mode:"off"` add friction.
2. **OpenClaw has no turn or tool-call cap.** In an early run the scripted model got stuck in a loop. OpenClaw kept calling for 2,275 messages, with an estimated 2.67 M input tokens per call at the end, until it was killed. The config schema has only wall-clock limits (`agents.defaults.timeoutSeconds`, `tools.exec.timeoutSeconds`). Against a real provider, that would drain the plan allowance. **So the broker's model egress must enforce per-task call and token budgets.** It can, because it is the only route to a model.
3. **Broker tools are reached through tool search.** The model sees `tool_search`, `tool_call` and `tool_describe`, not `broker__*` directly. It takes two hops: search, then call. The search result showed the tool's input schema as `"unknown"`. A real model may also need `tool_describe`, which would be a third call. This works, but it costs latency and tokens on every effect. A follow-up should check whether config can promote MCP tools to the direct surface. Not verified.
4. **Name collision.** OpenClaw has a built-in tool named `intent` (memory-core "standing intents"). The MCP prefix (`broker__`) avoids a clash, but the broker vocabulary should not rely on the bare word.
5. **Credential traps inside the guest:**
   - The `secrets` tool asks the human for credentials and stores them in the guest.
   - OAuth provider logins and MCP `auth:"oauth"` keep refresh tokens in `state/openclaw.sqlite`.
   - All of these must stay denied or unused (CRED-1). Never run `openclaw onboard` with real logins inside a guest.
6. **Tool results come back wrapped as `EXTERNAL_UNTRUSTED_CONTENT`.** That includes broker results. It's useful injection hygiene, and the broker should not count on its text being read verbatim.
7. **One unexplained DNS lookup.** The first gateway run (g1) tried to resolve a name. It made 3 attempts, to the host's 8.8.8.8 and 8.8.4.4 resolvers, and failed closed. Four later gateway runs with the DNS sink saw no queries, so the name is unknown. It is harmless under default-deny, but it is unexplained.
8. **npm skipped the install scripts** (npm's `allowScripts`), including OpenClaw's `postinstall-bundled-plugins`. Nothing the spike used was missing. The image build should decide this explicitly.
9. **Footprint matters at the floor (HW-4).** One idle gateway after a turn is about 1.6 GB RSS, plus 735 MB on disk, plus 27 s cold start. On the 8 GB N95, once the host, broker and local inference take their share, that leaves room for roughly 1–2 concurrent OpenClaw machines [inference]. That feeds S3's density numbers and CAP-1's N.

## Proposed SPEC.md diff (for v0.12; L1 to merge, Mark approves)
```diff
 - **ARC-3** Agent runtimes MUST run unmodified where their tool/plugin interfaces suffice. A runtime fork is permitted only with a recorded "interface X insufficient because Y."
+  - Qualified (S4, OpenClaw 2026.9.8): unmodified, config only. Record per qualified guest version.
+- **ARC-5** The broker's guest interface is: (a) model access as standard provider endpoints (OpenAI- and Anthropic-compatible) where the guest holds only a placeholder credential; (b) broker tools over MCP (streamable HTTP); (c) owner messages delivered into the guest's own inbound API. Guest-side channel plugins are not used.
+- **ARC-6** Guest configuration is defense in depth only. Containment MUST hold with a guest that rewrites its own configuration (root inside, REV-1).
 ...
+- **OP-8** The broker's model egress MUST enforce per-task limits on model calls and tokens, independent of the guest. Guests may loop without bound.
 ...
 - **CRED-1** ... readable by any model-directed process.
+  Guest profiles MUST disable credential-acquiring guest features (e.g. OpenClaw's `secrets` tool, in-guest OAuth logins).
```
For S3 and HW-4: budget about 1.6 GB RSS per OpenClaw machine when sizing CAP-1 at the floor.

## Reproduce
```sh
# Node >= 24.16 on PATH; root for unshare; strace installed
npm install openclaw@2026.9.8 && export OPENCLAW_BIN=$PWD/node_modules/.bin/openclaw
spikes/S4-openclaw-guest/run_guest.sh   /tmp/s4/a "SCENARIO:effect_request go" --agent main --session-id a
spikes/S4-openclaw-guest/run_gateway.sh /tmp/s4/g "SCENARIO:exec go"
```
Each output directory holds `broker.jsonl` (every request the broker saw), `dns.jsonl`, the strace log, `time.txt`, and the reply.

## Model usage spent
Not metered. The harness can't read the usage screen (PLAN §4A B-6). Estimate: about 0.4 M tokens of context processed across this thread and one inventory sub-agent (~0.2 M), mostly cached reads. That is roughly 1.5–3% of a weekly allowance [inference], within the ~3% soft target. Mark's next usage screenshot can recalibrate this.
