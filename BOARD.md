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
