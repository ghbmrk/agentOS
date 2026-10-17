# TRUST-policy-before-lockout: A failed trust puts the approved boot paths back

Board section: issue #1781. Class: release (HW-5a: a modified boot path cannot unlock unattended). Tier: A (`broker/cmd/agentos-egress` is tier A; `python3 tools/risk_tier.py` prints A). Builder: strongest model. Usage estimate: 80k tokens, checkpoint at 65k.

**Why (facts).** `enroll` (`broker/cmd/agentos-egress/trusted.go`) adds the current boot path's signed policy to the policy file (`addPolicy`) before it takes the TPM lockout (PIN trust) and adds the vault slot. When a later step fails, the owner is told the PC is not trusted ("nothing was changed", `custody.go` `errHostNotSaved`), but the added policy stays. An earlier slot for this PC then unseals on that boot path too, so a trust that failed has approved a new boot path for unattended unlock.

## Requirements (from SPEC.md)

- **HW-5a** "... the trusted-host vault slot (CRED-8) is sealed to the PCRs that measure them, so a modified boot path cannot unlock unattended."
- **CRED-9** "Adding or removing a trusted host is a tier-4 action (CH-3)." A failed add must not take partial effect.
- **HW-8** the lockout and TPM changes of a failed PIN trust are undone (already covered by `giveBack`; this package checks the policy file too).
- Package IDs: **TRUST-PBL-1** every failure after `addPolicy` in a trust (TPM refuses the lockout change, lockout owned elsewhere, vault sync fault, staged-key sync fault) leaves the policy file byte-for-byte as before and no new TPM slot. **TRUST-PBL-2** a PC trusted on boot path A, then given a failed trust while booted on B, does not unlock unattended on B and still does on A. A slot change that errors with `vault.ErrSlotDecided` keeps the policy (it did trust the PC, S2-2).

## Acceptance tests

**Acceptance tests:** `broker/cmd/agentos-egress/trusted_test.go::TestFailedPINTrustLeavesTheBootPathsAsTheyWere` (TRUST-PBL-1) and `TestFailedTrustDoesNotApproveANewBootPath` and `TestDecidedTrustKeepsTheNewBootPath` (TRUST-PBL-2), run with `AGENTOS_REQUIRE_SWTPM=1`.

## Scope (files)

`broker/cmd/agentos-egress/trusted.go`, `broker/cmd/agentos-egress/trusted_test.go`, `broker/cmd/agentos-egress/ASSUMPTIONS.md`, `briefs/TRUST-policy-before-lockout.md`. `rotation.go`, `server.go`, `main.go` and `custody.go` are owned by parallel builds and not touched.

## Follow-ups

The vault entries a failed trust may keep (PCR policy key, DA originals, a lockout auth kept on an ambiguous TPM error) make `errHostNotSaved`'s "nothing was changed" overstate; rewording it lives in `custody.go` and is a separate issue.

## Done

CI green and both acceptance tests pass on swtpm.
