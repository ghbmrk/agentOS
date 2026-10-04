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
| Proposed | External-drive-only (no internal install) | Not yet confirmed |
| Pending | License | Before first public release (OSS-12) |
