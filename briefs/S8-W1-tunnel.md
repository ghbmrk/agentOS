# S8-W1-tunnel: Codex worker egress through the broker proxy

Board section: Release rows carried from LATER.md (2026-10-10). Source: work item #1014 (from the S8-W1a inventory, #543; `docs/security/provider-worker-isolation.md` row "Provider inference tunnel"). Tier A (egress, vm). On G1's plan path: fourth in the chain #808 → #807 → #1015 → this → CAP-11-plan (#1314) → #1264. No real login uses it before S8-live (#809).

**Re-scoped 2026-10-13 (D-114).** Codex (ChatGPT plan) is the default plan route and runs broker-held: the worker holds placeholders, and the vault process injects the real login at declared endpoints (CRED-5, ADP-10). The broker must therefore see each request, so this row is no longer a CONNECT/SNI tunnel. The tunnel design was written for a worker-held Claude CLI; it moves to the Claude opt-in row (#1380) and is in this file's history at 509f094.

**Why.** At current main a worker has no network and no broker socket (`broker/workers` package doc), and the guest-facing egress proxy refuses every `CONNECT` (`broker/egress/proxy.go`, ASSUMPTIONS E12). A Codex worker needs exactly one way out: to its declared OpenAI endpoints, through the swap in `broker/egress/exchange.go` (#426).

**Requirements:** CRED-5 broker-held (placeholders in the CLI; injection at declared endpoints only, including the refresh), CRED-1 (no real value in the worker), A14 ("a provider agent in a worker cannot reach any host but its provider's declared model endpoints"), DEV-2 and E12 (no home-network or non-global address, also by rebinding), RES-5 and OP-8 (the run is metered; quota read from the declared headers is advisory), A3 (a plan route run as a provider-agent worker reaches its provider through this path).

**Ownership.** #807 owns the image, the pinned Codex CLI and its managed config, including the `base_url` and `CODEX_REFRESH_TOKEN_URL_OVERRIDE` that point at the forwarder this package adds. #1015 owns the vault entry and the placeholder `auth.json`. This package adds the worker's path out and the declared endpoint list.

**Change.**
- **Who serves it.** A new listener in the vault process (`broker/cmd/agentos-egress`), which already holds the netguard pins, the vault and the only outbound network. The guest-facing proxy is unchanged and keeps refusing `CONNECT`; a regression test pins that.
- **Endpoint.** One unix socket per provider worker, created only for a worker whose spec names a broker-held provider, bound into that worker. An in-worker forwarder on loopback relays the CLI's requests to it.
- **Declared endpoints only.** The listener forwards a request only when its method, host and path match the provider declaration (CAP-11-plan): for Codex, the responses endpoint, the models list and the token refresh (`auth.openai.com/oauth/token`, reached through the refresh override). Every other request is refused and journaled (host and path only). S8 measured about 20 side calls (analytics, plugins, update checks); they fail by absence, not by a deny list.
- **Swap.** Each forwarded request goes through the existing `Swapper`: placeholders are replaced with the real values from the vault entry (#1015) at declared header positions, and refresh responses are swapped back to placeholders, all or none. This package wires it; it does not change the swap rules.
- **Plain HTTP or TLS to the forwarder.** The builder measures whether the pinned CLI accepts a plain-HTTP `base_url` and refresh override on loopback. If it does, no TLS terminates in the worker. If it does not, the forwarder terminates TLS with a per-box CA passed in `CODEX_CA_CERTIFICATE`, whose key never enters the worker. Record the finding in `broker/egress/ASSUMPTIONS.md`.
- **Broker resolution.** Upstream names resolve through the box's `netguard.Policy` dialer (E12), on every lookup; a non-global or home-prefix answer is refused, and the dial goes to the approved address.
- **Metering.** Each request is journaled as part of one run (provider ID, worker, endpoint, bytes, duration) and charged to the creator's reservation. The `x-codex-*` quota headers S8 found are recorded per declared pool as advisory (RES-5).
- **Tools have no network.** The forwarder's loopback and the socket path are unreachable from Codex's tool subprocesses (#807's sandbox). A tool holding the placeholder could otherwise spend the owner's plan.

**Simpler than the tunnel.** No ClientHello parsing, no SNI binding and no `SO_PEERCRED` question under gVisor, because the broker reads each request and the worker holds nothing worth stealing. The tool-network cut stays, since the placeholder still spends the plan through the proxy.

**Tests first.** A stub CLI's request to a declared endpoint reaches a stub upstream with the canary value injected, and the worker side sees only placeholders. A request to an undeclared host or path, a `CONNECT` and a declared host that rebinds to a private address are each refused and journaled without payload. A refresh through the stub swaps back to placeholders and updates the vault entry before release (#1015). The guest-facing proxy still refuses `CONNECT` (regression). A worker without a broker-held provider gets no socket. From a tool subprocess in the worker, loopback and the socket path are unreachable. Quota headers land as advisory pool readings. The image test fails if `base_url` or the refresh override does not point at the forwarder.

**Revert mutants (each must turn a test red).** Forward an undeclared path. Skip the swap on a declared endpoint. Re-resolve the name at dial time. Let the guest-facing proxy accept `CONNECT`. Create the socket for a worker without a broker-held provider. Leave the socket reachable from tools.

**Threats Security must check.**
- An undeclared endpoint reached through a declared host (path confusion, encoded paths, a redirect the forwarder follows).
- Injection into a header or body position the declaration does not name.
- The forwarder or the per-box CA key reachable from tools or visible in `/proc`.
- A refresh response that reaches the worker unswapped on an error path.
- Provider terms: Codex's terms were read in S8 (`spikes/S8-provider-workers/CODEX-TERMS.md`, #810); the route stays unconfirmed under D-061 until consent is recorded (CRED-5c).

**Needs:** #807 (image, managed config, tool sandbox; the path must not ship before tools are cut off from loopback). #1015 (vault entry, placeholders, the worker spec field naming the provider). Can build against stubs in parallel with #1015 if the spec field is agreed first.

**Out of scope.** The vault entry and placeholders (#1015), the image and CLI config (#807), the route and its guest tool (CAP-11-plan), page sign-in (#1264), the Claude opt-in tunnel (#1380), live checks against real provider edges (S8-live, #809).

**Scope:** `broker/egress/worker.go` (new), `broker/egress/*_test.go`, `broker/egress/ASSUMPTIONS.md`, `broker/cmd/agentos-egress/main.go`, `broker/cmd/agentos-egress/server.go`, `broker/cmd/agentos-egress/*_test.go`, `broker/vm/gvisor/gvisor.go` (socket mount), `broker/vm/gvisor/*_test.go`, `broker/vm/worker.go`, `broker/vm/*_test.go`, `broker/cmd/agentosd/main.go` (wiring), `image/mkosi/*` (forwarder only), `image/ASSUMPTIONS.md`, `tests/test_image.py`, this brief.

**Usage estimate:** 110k tokens, less than the tunnel because nothing parses TLS. Split if past the checkpoint without green: (a) the listener with declared endpoints and swap wiring, (b) the forwarder and image settings. Builder model: Opus-class (tier A).
