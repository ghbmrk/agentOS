# LATER: first-release critical path and backlog
Generated 2026-10-07 by the COST thread's audit; the coordinator updates it. Rows marked LATER are not started until the first release ships (DECISIONS.md, 2026-10-07). Promote a row by moving it to "Release" with the acceptance test it now blocks.

## Summary
Non-merged rows audited: 129. Release: 48 (11 marked unsure). Later: 14. Stale: 67, of which 33 are inferred from code on origin/main because the clone is shallow.
No security-fix row (SR2-*) is classed Later. P2-1 (host image, PR #41) has no board row but blocks IMG-1, HOST-1a/1b/1c part 2 and W3-builder-ship.

## Release (needed for A1–A15 or an invariant)
| ID | Needed for | Note |
|---|---|---|
| S5 | A5, A13 | CRED-4 action protocol; live run blocked on network policy |
| S8-W1 | A14, CRED-5 | Blocks every worker-held route; credential invariant |
| S8-live | A3 (CAP-11) | Needs Mark's Claude and ChatGPT plans |
| S8-codex-terms | A3, CRED-5 (unsure) | Decides Codex custody; a Claude plan route may already satisfy A3 |
| S1 | A1 (G1) | Test kit ready; waits on Mark's hardware |
| S2 | A1, A3 | Modem SMS and voice; waits on Mark's modems |
| P2-4-hw | A8 | Real-TPM trusted-host run; risk 14 |
| P3-4b | A11 (unsure) | Loop 2 active testing; Mark deferred 10-05, A11 loop-2 part stays open |
| P3-6e | A11, CHG invariant (unsure) | Security R1 condition before the model-backed builder is wired |
| UPD-b | A1, A14 (UPD-3) (unsure) | Update before accounts connect |
| CH-20w | A15 (CH-20) | Evidence delivery through the vault-held mail adapter |
| CRED-4b | A5, A13 | Credentialed browser executor; sessions only in the vault process |
| ADP-8 | A13 (ADP-8) | Mislabelled-draft check blocks adoption |
| ADP-5 | A13 | Desktop executor and kiosk-escape test; blocked on CRED-4b |
| OSS-6s | A12 | Publication sender, idempotent by day and batch |
| OSS-6e | A12, clean-room invariant | Security ruling on #180: floor holds across restarts |
| OSS-10w | A12 (unsure) | Follow-fork wiring; OSS-1–13 are in A12's requirements |
| IMG-1 | A1 | CI scan for per-owner secrets in the image; blocked on P2-1 |
| P2-2w | A1, A14 (ARC-2) | Local UI process; sub-rows a, b merged, c and d open |
| P2-2w c | A1, A14 | Setup into agentosd; Security L6, L7 MUST |
| P2-2w d | A1, A3, A14 | Turns LocalUI on; unblocks approvals and CH-20p |
| SR2-3g | A5, A6 (security) | No host path in agent-visible tool errors |
| SR2-3h | A5, A6 (security) | runsc messages never reach the guest |
| SR2-4i | A2 (RES-2) | Host image enables iocost; blocked on host image |
| CH-21 | A14 (CH-21) | Name, first-person voice, spoofed NAME refused |
| HOST-1a | A1 (HW-8) | Part 2 needs P2-1 image |
| HOST-1b | A1 (HW-8) | Part 2 needs P2-2w live page |
| HOST-1c | A1 (HW-8, ONB-7) | Part 2 needs P2-2 |
| HOST-1e | A1 | Host-untouched hash harness |
| W2 | A12 leakage audit (unsure) | Recall as guest tool with vault-held key |
| PE4 | A11 (unsure) | Preempted Loop 2 fix never retried; #112 predates shallow history |
| PE7-bus | A11, A2 (unsure) | Condition on the events-bus package; floor host |
| PE7-call | A11, A2 (unsure) | Condition on the inbound-call package |
| W3 | A11 | Learning process; steps 3a, 3c open |
| W3-goal | A10, A11 (unsure) | Goal IDs for compiled skills |
| W4 | A11, A15 | Managed tree to the agent machine |
| W3-values | A10 | Param values for compiled skills |
| W3-values-mix | A10 (unsure) | Leak-guard follow-up to W3-values |
| W3-builder-ship | A11 | Builder defaults; P2-1 side queued |
| W3-forget | A14 (CAP-3) | Owner FORGET; split a, b |
| W3-forget-b | A14 (CAP-3) | Authenticated forget log over restores; Security C3 |
| W5 | A11, A15 | Owner channel for loops, digest, hint emitter |
| W5a-resume | A14 (security) | Per-grant resume needs a fresh bound code; Security R2 |
| W5b | A7, A11 | Loop 3 update checks as a scheduler source |
| W5c | A12 | Clean-room builder in the scheduler |
| W6 | A8 (REC-1–3) | Recovery into vault process and local UI |
| W7 | A10, A15 (CAP-4–6) | Compiled skills live; attention optimizer; blocked |
| W9 | A15 | Default-on-timeout questions live |

## Later (backlog; do not start before first release)
| ID | Why it can wait |
|---|---|
| P2-8b | Deferred re-encrypt after trusted-PC removal; slot removal already covers CRED-9 |
| P3-6d | Digest wording for deleted procedures; no A-test needs it |
| P3-8b | Question batching and ask_by; A15 needs only default-on-timeout |
| CH-20p | Page view of kept replies; A15 needs delivery, not this view |
| CH-20a | Attachments conflict with security C4; needs review; not in A15 |
| CH-20m | MORE command for redirected replies; convenience |
| P2-2a f1 | L3 SHOULD on page wording after a changed item |
| ADP-13 | Optional box mailbox; no A-test needs it |
| HOST-1d | Optional internal-disk opt-in (HW-8a); A1 requires disks untouched |
| PE3 | Potency follow-up on replay-interruption counting |
| W3-off-a | STATUS wording goes dynamic; polish |
| W3-implicit | Potency C2 outcome label; refinement of attention optimizer |
| W8 | Owner builds; no brief, no A-test names it |
| W9a | Question follow-ups from the #95 lens gate; no A-test needs them |
| P2-2w c1 f1 | Record the Security L6-L8 conditions from the P2-2w plan review in DECISIONS.md or reviews/security/; c1 worked from the BOARD row and P4 |
| P2-2w c1 f2 | A crash between the enrollment seal and deleting `owner-totp-pending` leaves that copy of the channel seed in the vault (and backups); unreadable once sealed. Fix: delete a leftover pending entry when a sealed vault opens |
| P2-2w c1 f3 | No negative test for a peer uid on the `/enroll` routes; the `verify.sock` SO_PEERCRED listener is unchanged and already tested |

## Stale board rows (merged per git log)
Rows marked "(shallow)" show only code on origin/main plus the last commit touching it: this clone is shallow, so older merge commits are not visible. Verify those before editing the board.
| ID | Commit |
|---|---|
| H1 | 00c298d (shallow, tools/metrics.py) |
| P0X | cada7c1 (shallow, SPEC.md v0.12) |
| S8 | 03641d1 (#186 cloud part and spec diff) |
| P1-1 | 05913d0 (shallow, broker/journal) |
| P1-2 | 7ff7417 (shallow, broker/daemon) |
| P1-4 | f19f97c (shallow, broker/vm) |
| P1-7 | 847ea23 (shallow, broker/guest) |
| P2-grants | a390f03 (shallow, broker/grants) |
| P2-rev3 | 04be62e (shallow, broker/reversible) |
| P2-gr8 | a390f03 (shallow, broker/grants) |
| P2-2 | a0bb643 (shallow, broker/localui; LocalUI still off) |
| P2-7 | e7c419b (shallow, broker/modelroute) |
| P2-3 | 46e3885 (shallow, broker/modem) |
| P2-3b | 27f6fe9 (shallow, broker/sipsign) |
| P2-3c | 0a6c2c7 (#159 part 5) |
| P2-3w | 65b48ef (#170 part 1; later parts not on board) |
| P2-6m | c5feca1 (shallow, broker/mail) |
| P2-4a | ad55ae2 (shallow, broker/vault) |
| P2-4b | 6303190 (shallow, broker/tpmseal) |
| P2-4c | ad55ae2 (shallow, broker/vault) |
| P2-4d | ad55ae2 (shallow, broker/vault) |
| P2-4g | ad55ae2 (shallow, broker/vault) |
| P2-4h | ad55ae2 (shallow, broker/vault) |
| P2-2a | 6239bd4 (#178 part 2) |
| P2-2w a | b00db30 (#184) |
| P2-2w b | 0302131 (#189) |
| P3-1 | cff139d (shallow, broker/change) |
| P3-1a | 30d601c (shallow, broker/replay) |
| P3-1b | cff139d (shallow, broker/change) |
| P3-2 | 0302131 (#189; shallow, broker/loops) |
| P3-3 | 5980098 (shallow, broker/recall) |
| P3-3b | 44975b6 (2/2, #59; wired in #152 469c644) |
| P3-4 | c5feca1 (shallow, broker/loops Guard) |
| P3-5 | 4672fe8 (shallow, broker/maintain) |
| P3-6 | 04be62e (shallow, broker/compile, skill) |
| P3-6b | 04be62e (shallow, broker/attention) |
| P3-7 | 847ea23 (shallow, broker/guest goal.go) |
| P3-8 | 2b1bd8a (shallow, broker/question) |
| P4-2 | d6a5046 (shallow, broker/cleanroom) |
| P4-3 | 8bab3fe (shallow, broker/update) |
| RES-2c | 9fa31bc (#140) |
| CAP-8b | 244974b (#150) |
| CAP-8c | c4c2366 (#166) |
| CAP-1 | 49cc421 (commit on main; item D merged via #166) |
| OSS-9 | 4329b1d (#180) |
| OSS-6c | 4329b1d (#180) |
| SR2-3 | a10b5fe |
| SR2-3i | d40fb31 (#174) |
| SR2-3d | d40fb31 (#174) |
| SR2-3f | f19f97c (#181, commit fcdce51) |
| SR2-3s | 847ea23 (#179) |
| SR2-5 | 2e85d06 |
| SR2-7 | 5cddc94 |
| SR2-8 | 64220e9 (#162) |
| SR2-9 | 64220e9 (#162) |
| CH-12s | a390f03 (#185) |
| HOST-1 | fa52b76 |
| HOST-1f | de01c80 (#188) |
| CI-SOAK | 8bab3fe (#187) |
| PE5 | 04be62e (#127) |
| PE5b | 273b2c5 (#145) |
| PE7 | 135c0c0 (#153 part 3) |
| W5a | 3d2daab (#169) |
| W3-tasks | 538d180 (#160 part 2; wiring waits for forget action) |
| W3-forget-a | 05913d0 (#182) |
| W3-builder-image | 4b0d00e |
| W3-builder-tune | 61cfd90 |

## Reuse candidates
| ID | Component | Why |
|---|---|---|
| CRED-4b, S5 | Playwright (Chromium over CDP) | Drives pages inside the sandbox; the narrow action protocol wraps it |
| ADP-5 | cage (Wayland kiosk compositor) | Single-app kiosk with no shell or file manager; add file-dialog confinement |
| HOST-1d | cryptsetup / LUKS2 | Vault-keyed disk encryption without custom crypto |
| SR2-4i | systemd resource control (IOWeight=, CPUWeight=) | Sets io.weight and cpu.weight per slice; add iocost QoS on the image |
| UPD-b | systemd-sysupdate (S7 stack) | First-boot update-before-trust already fits the chosen image stack |
