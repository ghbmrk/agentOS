# BOARD

States: `queued` → `building` → `in review` → `merged` | `escalated` | `dropped`

## Phase 0: harness and risk spikes

| ID | Package | Needs | State |
|---|---|---|---|
| H0 | Repo scaffold: docs, trace tool, CI, PR template | — | merged |
| S7 | Host foundation: compare 2–3 immutable-image options (A/B updates, Secure Boot shim, USB boot, build time) | Cloud only | queued |
| S3 | Agent machines at 8 GB: microVM vs container+sandbox; snapshot/fork/rollback timings; max concurrency | Cloud first, then N95 | in review (cloud part; Firecracker + N95 timings need hardware) |
| S4 | OpenClaw unmodified as a guest via broker tools; record any missing seam. Result: **yes**, config only, no patch ([result](spikes/S4-openclaw-guest/RESULT.md)) | Cloud only | in review |
| S5 | Credentialed browser: narrow action protocol vs 5 real sites, no arbitrary JS | Cloud, test accounts | queued |
| S6 | Consumer AI CLIs in no-tools relay mode | Mark's accounts | queued |
| S1 | Screenless USB4-SSD boot on ≥3 unmodified PCs (≤1 keypress) | **Mark: hardware + hands** | blocked on hardware |
| S2 | USB LTE modem: SMS and voice under Linux | **Mark: 2 modems + SIM** | blocked on hardware |

Exit of P0: spike results → spec v0.12 diff → Mark approves → budget re-estimate.
