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
| Proposed | External-drive-only (no internal install) | Not yet confirmed |
| Pending | License | Before first public release (OSS-12) |
