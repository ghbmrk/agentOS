# BOARD

States: `queued` → `building` → `in review` → `merged` | `escalated` | `dropped`

## Phase 0: harness and risk spikes

| ID | Package | Needs | State |
|---|---|---|---|
| H0 | Repo scaffold: docs, trace tool, CI, PR template | — | merged |
| S7 | Host foundation: compare 2–3 immutable-image options (A/B updates, Secure Boot shim, USB boot, build time) | Cloud only | merged: [result](spikes/S7-host-image/RESULT.md), systemd image stack on Debian 13; HW-5a decided |
| S3 | Agent machines at 8 GB: microVM vs container+sandbox; snapshot/fork/rollback timings; max concurrency | Cloud first, then N95 | merged (cloud part); Firecracker + N95 timings wait on hardware |
| S4 | OpenClaw unmodified as a guest via broker tools; record any missing seam. Result: **yes**, config only, no patch ([result](spikes/S4-openclaw-guest/RESULT.md)) | Cloud only | merged |
| S5 | Credentialed browser: narrow action protocol vs 5 real sites, no arbitrary JS | Cloud (needs network access to the 5 sites); demo logins stand in for test accounts | building: fixture suite passes ([interim result](spikes/S5-browser-actions/RESULT.md)); live run blocked on network policy |
| S6 | Consumer AI CLIs in no-tools relay mode | Mark's accounts | queued |
| S1 | Screenless USB4-SSD boot on ≥3 unmodified PCs (≤1 keypress) | **Mark: hardware + hands** | test kit ready ([checklist](spikes/S1S2-testkit/CHECKLIST.md), [shopping](spikes/S1S2-testkit/SHOPPING.md)); waiting on hardware |
| S2 | USB LTE modem: SMS and voice under Linux | **Mark: 2 modems + SIM** | test kit ready (same image); waiting on hardware |
| P0X | Spec v0.12 (S3, S4, S7, HW-5a) + budget re-estimate (PLAN.md §4B) | — | in review |

Exit of P0: spike results → spec v0.12 diff → Mark approves → budget re-estimate.

## Phase 1: core in a VM

Started before spec v0.12 on parts unlikely to change; each package lists its spec assumptions.

| ID | Package | Needs | State |
|---|---|---|---|
| P1-1 | Journal and intent engine (OP-1–7), Go library with property tests ([assumptions](broker/journal/ASSUMPTIONS.md)) | Cloud only | in review |
| P1-2 | Broker skeleton: sockets, admission classes, STOP/STATUS without inference (ARC-2, CH-2) ([assumptions](broker/daemon/ASSUMPTIONS.md)) | P1-1 | in review |
| P1-3 | Vault and credentialed egress proxy: encrypted vault, key injection into declared inference endpoints only, relay body rules, redaction (CRED-1, CRED-5, CRED-7; ADP-10 partial) ([assumptions](broker/egress/ASSUMPTIONS.md)). **Conditions for P1-7:** do not serve `Proxy.Handler` to a machine until OP-8 metering exists, or at least `Config.Cap` is set; OP-8 lands before or with P1-7; each machine's listener is reachable only from that VM (per-VM vsock CID or tap); A14 re-proves CRED-1 and CRED-5 end to end through the wired listener; no build loads the vault data key from a plaintext file or env var outside tests until P2-4; wire `Config.Label` to each machine's REV-5 label (until then provider-side tools are denied to every machine). | P1-2 | merged |
| P1-4 | Agent-machine lifecycle: create, snapshot, fork, diff, merge, rollback, rebuild, destroy under gVisor with cgroup budgets and preemption (REV-1, REV-4, ARC-4, RES-1, RES-2) ([assumptions](broker/vm/ASSUMPTIONS.md)) | P1-2 | in review |
| P1-6 | Canary harness (A5) and dependency audit harness (A9) as permanent CI jobs ([assurance/README.md](assurance/README.md)) | Cloud only | merged |
| P1-5 | Owner channel on a modem simulator: SMS, two-tier approval codes, tiers, inline unlock, code hygiene, disclosure and commitment filters (CH-1–4, CH-10–14, CH-16, CH-18, CH-19, ADP-11) ([assumptions](broker/owner/ASSUMPTIONS.md)). Carry-forward: P2-2's local UI must offer RESUME and a local unlock that clears challenge mode (O4) as defense in depth; P1-7 tells the owner what a restart dropped (`Boot`) and closes approval-pending intents with no live request | P1-2 | merged |
| P1-7 | OpenClaw as first guest: per-machine guest socket mounted into gVisor, broker tools over MCP with Step after each call, owner chat to the guest and back, OP-8 spend meter, egress denials journaled, verb-class gate, REV-5 labels to the proxy, A14 through the guest socket, A9 offline scenario, real OpenClaw run in CI (ARC-6, ARC-7, OP-8, REV-1, REV-5, OP-1, ADP-10) ([assumptions](broker/guest/ASSUMPTIONS.md)). Carry-forward: P2-4 serves the model route from a process holding the unlocked vault, with `Label: vm.Manager.DataLabel` (G8, E10), and checks OpenClaw resumes after a 429 extension; the grants/approval-policy package takes P1-5's approval-pending close-out (G12), records the requesting machine and label at submit and re-authorizes a repeated `request_id` from a higher-label fork (REV-5, OP-1), and sends denied effects the owner should see as CH-12 approval requests; size the meter defaults from measured task usage so a normal day never prompts (G7); put agent replies under CH-15 pacing (G13); keep a warm OpenClaw template checkpoint per image (S3: 2-4.5 s against 56 s cold); P2-1 asserts the image holds no socket files (V15) | P1-3, P1-4, P1-5, P1-6 | in review |

## Phase 2: real hardware, and the cloud parts first

| ID | Package | Needs | State |
|---|---|---|---|
| P2-grants | Grants and approval policy: grants as intents, fixed verb list, approval requests through the owner channel batched by tier, pre-allowances as predicates over verified fields, ADP-11 replies with undo, PAUSE and REVOKE by text, OP-3 recheck, restart re-issue of approval-pending intents with fresh per-intent codes, machine and label recorded per intent (REV-2, OP-3, OP-4, OP-5, ADP-1, ADP-2, ADP-9, ADP-11, CH-3, CH-10, CH-13, CRED-6) ([assumptions](broker/grants/ASSUMPTIONS.md)). Carry-forward: P2-2 sets `LocalUI` and calls `ConfirmLocal`; adapters (P2-6, P2-7) supply executors and `Verifier`s; P2-4 wires the vault's redactor into `daemon.Config.Redactor`; the reply-composer pipeline sets `Isolated` | P1-7 | in review |

P1-4 follow-ups (from the #23 review), for P1-7 or the loop scheduler:
- Re-admit preempted experiments: nothing calls `Manager.Resume` with retries yet (Potency).
- Long experiments take an idle-time full checkpoint, so repeated preemption still makes progress (Potency).
- After a broker restart, accepted work resumes once the journal reconciles, and the boot text names the resumed tasks (UX).
- Guest sockets follow the B8 per-machine identity rule when P1-7 mounts them (V15, Security). Done in P1-7: identity is the socket (G1).
- On the N95, measure zram together with the 1/16 `memory.high` margin (Potency).

## Phase 2: real hardware (cloud parts)

| ID | Package | Needs | State |
|---|---|---|---|
| P2-2 | Owner Card and local web UI: card generation and printable card with QR codes, paper grid and recovery sheets (ONB-7; [assumptions](broker/card/ASSUMPTIONS.md)); local UI with setup steps 5-6, sign-in, local unlock that clears challenge mode, STOP and RESUME, CH-9 guards and captive portal (CH-7–9, ONB-1, ONB-3–8; [assumptions](broker/localui/ASSUMPTIONS.md)). The access point driver is a seam (`localui.AccessPoint` plus generated hostapd, dnsmasq and nftables configs) for P2-1 on hardware. Wiring: the modem loop calls `Server.OfferText` until setup has an owner; `Hooks.Finish`'s caller starts the owner channel, calls `SetOwner`, and sends `AllSetText` | P1-5 | in review |
| P2-7 | Provider adapters: model router (CAP-9) over two API routes, OpenAI and Anthropic, behind the one chat-completions guest interface; failover on exhaustion, grants and data labels checked before sending, measured routes and Loop 1 rule candidates ([assumptions](broker/route/ASSUMPTIONS.md)). A3's consumer route waits on S6. Wiring: serve `Router.Handler` behind the OP-8 meter in place of the raw proxy | P1-3, P1-7 | in review |
| P2-4a | Vault passphrase key slot and vault process: Argon2id passphrase slot with a TPM seam, `agentos-egress` holding the unlocked vault and serving the model router (P2-7) and proxy behind the route `agentosd` forwards, with provider usage passed back to the OP-8 meter, unknown-host unlock by passphrase plus code-generator code (CRED-8; carries P1-7's G8) ([assumptions](broker/egress/ASSUMPTIONS.md), K1–K9). Carry-forward: P2-2 scans the passphrase on the local page, offers the grid challenge, and texts the owner about unlock pending, unlocked, wrong code with tries left, and lockout with retry time, plus a "Box locked after restart" reply, with P2-3 (K6); a verify operation sharing one last accepted step on the vault process gives the owner channel its high-tier codes (K7). The router wiring (K9: per-request label and auditor in `route`, the `Agentos-Usage` trailer to `meter.Report`) is part of this package and depends on P1-7 (#24) | P1-3, P1-7, P2-7 | in review |
| P2-4b | Trusted-host TPM slot (optional boot PIN), N95 Argon2id tuning, TPM NV rollback counter (CRED-8, CRED-9, V6) | **Mark: hardware** | queued |
