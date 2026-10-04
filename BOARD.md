# BOARD

States: `queued` → `building` → `in review` → `merged` | `escalated` | `dropped`

## Phase 0: harness and risk spikes

| ID | Package | Needs | State |
|---|---|---|---|
| H0 | Repo scaffold: docs, trace tool, CI, PR template | — | merged |
| S7 | Host foundation: compare 2–3 immutable-image options (A/B updates, Secure Boot shim, USB boot, build time) | Cloud only | in review: [result](spikes/S7-host-image/RESULT.md), rec. systemd image stack on Debian 13; needs HW-5a decision |
| S3 | Agent machines at 8 GB: microVM vs container+sandbox; snapshot/fork/rollback timings; max concurrency | Cloud first, then N95 | in review (cloud part; Firecracker + N95 timings need hardware) |
| S4 | OpenClaw unmodified as a guest via broker tools; record any missing seam. Result: **yes**, config only, no patch ([result](spikes/S4-openclaw-guest/RESULT.md)) | Cloud only | in review |
| S5 | Credentialed browser: narrow action protocol vs 5 real sites, no arbitrary JS | Cloud (needs network access to the 5 sites); demo logins stand in for test accounts | building: fixture suite passes ([interim result](spikes/S5-browser-actions/RESULT.md)); live run blocked on network policy |
| S6 | Consumer AI CLIs in no-tools relay mode | Mark's accounts | queued |
| S1 | Screenless USB4-SSD boot on ≥3 unmodified PCs (≤1 keypress) | **Mark: hardware + hands** | test kit ready ([checklist](spikes/S1S2-testkit/CHECKLIST.md), [shopping](spikes/S1S2-testkit/SHOPPING.md)); waiting on hardware |
| S2 | USB LTE modem: SMS and voice under Linux | **Mark: 2 modems + SIM** | test kit ready (same image); waiting on hardware |

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
| P1-7 | OpenClaw as first guest: per-machine guest socket mounted into gVisor, broker tools over MCP with Step after each call, owner chat to the guest and back, OP-8 spend meter, egress denials journaled, verb-class gate, REV-5 labels to the proxy, A14 through the guest socket, A9 offline scenario, real OpenClaw run in CI (ARC-6, ARC-7, OP-8, REV-1, REV-5, OP-1, ADP-10) ([assumptions](broker/guest/ASSUMPTIONS.md)). Carry-forward: P2-4 serves the model route from a process holding the unlocked vault (G8); the grants/approval-policy package takes P1-5's approval-pending close-out (G12) | P1-3, P1-4, P1-5, P1-6 | in review |

P1-4 follow-ups (from the #23 review), for P1-7 or the loop scheduler:
- Re-admit preempted experiments: nothing calls `Manager.Resume` with retries yet (Potency).
- Long experiments take an idle-time full checkpoint, so repeated preemption still makes progress (Potency).
- After a broker restart, accepted work resumes once the journal reconciles, and the boot text names the resumed tasks (UX).
- Guest sockets follow the B8 per-machine identity rule when P1-7 mounts them (V15, Security). Done in P1-7: identity is the socket (G1).
- On the N95, measure zram together with the 1/16 `memory.high` margin (Potency).
