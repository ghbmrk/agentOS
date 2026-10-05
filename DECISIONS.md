# DECISIONS

| Date | Decision | Source |
|---|---|---|
| 2026-10-04 | Rewrite from v0.10: unmodified agent runtimes as untrusted guests; trusted broker; reversibility is the trust boundary | Mark, project thread |
| 2026-10-04 | Pairing secret ships with the media (now the printed Owner Card) | Mark |
| 2026-10-04 | Frontier access: consumer logins preferred, API keys as a qualified fallback | Mark |
| 2026-10-04 | Accelerator support stays in MVP acceptance | Mark |
| 2026-10-04 | The box has its own phone number (its own SIM) | Mark |
| 2026-10-04 | The N95 / 8 GB machine is the floor, not the expected machine | Mark |
| 2026-10-04 | Credentials definitionally secure (Invariant C) | Mark |
| 2026-10-04 | Zero or near-zero external dependencies; no AgentOS-run services, relay, or app-store app | Mark |
| 2026-10-04 | Self-improvement and self-securing loops on spare capacity; on by default, modifiable | Mark |
| 2026-10-04 | Open-source contribution is clean-room only; no chance of exposing personal data | Mark |
| 2026-10-04 | Update to latest stable on first boot; channel-based cadence | Mark |
| 2026-10-04 | Build on the $200 Claude plan, usage credits off (the only hard cap) | Mark |
| 2026-10-04 | All other usage limits are flexible targets with checkpoints, not ceilings; weekly envelope adapts so allowance isn't wasted | Mark |
| 2026-10-04 | Package branches use a `pkg/<id>-<slug>` stem set by the coordinator, plus the server's session suffix; older `claude/…` branches are accepted when the PR title starts with the package ID | Mark, PR reviews thread |
| 2026-10-04 | Boot integrity (S7, proposed HW-5a): accept for MVP that Secure Boot covers only distribution-signed parts; AgentOS boot files are protected by a TPM policy seal on trusted hosts; unknown-host tampering is a documented risk (owner's guide: after losing custody of the drive, use only a trusted PC). Per-PC key enrollment rejected; own shim deferred past MVP | Mark, S7 thread |
| 2026-10-05 | First third-party Go module in the broker: `rsc.io/qr` v0.2.0 (QR encoding for the Owner Card and setup page). Accepted against "near-zero dependencies" because it is encode-only, BSD-licensed, has no dependencies of its own, and is vendored (`broker/vendor`), so builds never reach a module proxy (DEP-1); its one URL literal is a PNG metadata string recorded as inert in `assurance/dependencies.json` | P2-2 review (L3 + lens gate, PR #32) |
| 2026-10-04 | Unlock on an unknown PC needs the Owner Card's vault passphrase (entered on the box's Wi-Fi page) plus an approval code; the code alone never decrypts (CRED-8) | Mark, PR reviews thread |
| 2026-10-04 | Task text is private by default; the owner marks a task public with `PUBLIC` (D1) | Mark, PR reviews thread |
| 2026-10-04 | Context-scoped replies: yes, with alert; earned per account, verified thread starter, commitment filter (D2, ADP-11) | Mark, PR reviews thread |
| 2026-10-04 | Third-party calls and texts only on a second line, never the owner-channel number; spec now, build after S2 (F2, ADP-12) | Mark, arbitration |
| 2026-10-04 | Session unlock weekly by code-generator code, never a texted code (CH-19) | Mark, security review 1 |
| 2026-10-04 | Security fixes auto-stage only after one independent fast-channel attestation (D6, UPD-8) | Mark, security review 1 |
| 2026-10-04 | Optional boot PIN on trusted hosts, off by default (D7, CRED-8) | Mark, security review 1 |
| 2026-10-04 | Agent machines use gVisor at the floor; re-test Firecracker on the N95 and switch if it measures better (S3; ARC-5 already excludes namespaces alone) | Claude, auto-decided: no lens worse |
| 2026-10-04 | Host reference stack: Debian 13 systemd image stack (mkosi, systemd-sysupdate, dm-verity `/usr`, signed systemd-boot); fallback bootc on CentOS Stream 10 (S7) | Claude, auto-decided: measured pick per PLAN S7 rule |
| 2026-10-04 | Spec v0.12 folds S3, S4, S7 and HW-5a | Claude; P0 exit approval is Mark's |
| 2026-10-04 | CH-11 adds `RUN` (confirms a message held before a code-only unlock) and `UNLOCK <challenge> <code>` (after 10 wrong codes in 24 h, only attempts carrying a one-time challenge texted to the owner count; arbitrator's O4 ruling, PR #22) | Claude, auto-decided: security better, UX and potency not worse |
| 2026-10-04 | Pace: ~100% of the weekly limit used by each reset, spread evenly (~14%/day), with more parallel threads; replaces the 70% envelope ("faster and sooner, should be 100% at reset") | Mark, project chat |
| 2026-10-05 | Change-pipeline intents: `meta.change.*` is the one vocabulary for adopting, reverting, and changing adoption policy (P3-1, #34); `meta.skill` and `meta.release` stay unused journal constants until the journal package retires them. `meta.change.revert` and `meta.change.policy.off` are authority-narrowing (journal A9), so UNDO and turning auto-adoption or sharing off work during STOP | Claude, auto-decided on the #34 review: no lens worse |
| 2026-10-05 | TRACE.md is written only by the post-merge `trace` workflow on main; package PRs never commit it (CI fails one that does) and check markers against a tree CI regenerates, so the file no longer conflicts on every merge | Claude, tooling (reviewer's preferred fix) |
| 2026-10-05 | Boot PIN lockout (#42): the box takes the TPM lockout hierarchy only while the owner has a PIN on, and gives it back (empty authorization) when the PIN is turned off or the PC is untrusted; a lockout authorization already owned by another system refuses the PIN; the PIN minimum is 6 characters, counted as characters (CRED-8, D7) | Claude, arbitrator ruling, auto-decided: no lens worse |
| 2026-10-05 | PCR 7 (Secure Boot state) joins the trusted-host default PCRs (4, 7, 9, 12); firmware or db/dbx updates the box applies must re-predict or re-sign before the reboot, and a db change made outside the box is named to the owner as a Secure Boot change (HW-5a) | Claude, arbitrator ruling, auto-decided: no lens worse |
| 2026-10-05 | Reply rules allow light edits (PA2): ADP-11 earns after 20 unedited approvals with at most 10% of the last 30 answered replies edited; a NO, UNDO, or wrong verdict resets; ADP-9 templated rules keep any-edit-resets (#52) | Mark, project chat card and compiled skills thread |
| 2026-10-05 | Replay evaluator runs in `agentosd`, beside the machine manager and journal (W3a). This supersedes the arbitrator's earlier ruling on #56 that the evaluator run as its own process (`agentos-eval`) under its own uid. Replay machines' model calls go to the vault process like a live guest's, carrying only the tree's routing rule, which the vault process applies within the `-eval-from` machine's grants as private data (egress K10). Condition: replay never calls a model itself and the adoption verdict is deterministic broker grading, no LLM-as-judge (replay R10). Held-out cases (CHG-1) stay in the Pipeline in `agentosd` (PW1); candidate code runs only inside sandboxed `eval-` machines, which is the boundary that protects them. Router link waiver (#62): `agentosd` already reaches `route` through `guest`; this is accepted until W3's import-graph test, which is W3's first commit, and no PR wiring replay live merges before it passes. Security C1 as amended: an evaluation route may use only models priced per token at most like the active rule's dearest route (the vault process's own table); a dearer or unpriced one is refused and the tree is not evaluated, never a pass | Arbitrator, 2026-10-05 03:38Z (re-ruling) and ~03:52Z (C1 amendment, waiver), on W3a and #62, relayed via the PR reviews thread |
| Proposed | External-drive-only (no internal install) | Not yet confirmed |
| Pending | License | Before first public release (OSS-12) |
