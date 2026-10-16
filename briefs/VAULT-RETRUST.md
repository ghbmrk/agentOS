# VAULT-RETRUST: an interrupted re-trust of the same PC still restarts unattended

Board row: #1847 (class:release, from the review of the trusted-host wiring). Tier A (vault key slots, CRED-8).

## Failure path (verified on main)

Trusting a PC that is already trusted replaces its TPM slot (`AddSlot(f, sameHost)` from `broker/cmd/agentos-egress/trusted.go`). The change seals the next keys file into the vault, then writes it. A crash between the two (`crashKeysSealed`), or a failed keys write, leaves the file before on the drive. At the next boot `OpenSealed` with that PC's factor opens the old slot from the file before, and `checkKeys` rejects it because the next file no longer holds that slot: `ErrNoSlotOpens`, so the trusted PC boots as an unknown host and needs the passphrase and approval code (A8: a trusted host restarts unattended). `TestInterruptedSlotChange` and `TestRemovedSlotCannotReturnMidChange` cover removal and passphrase changes, not a same-host replacement.

## Fix

In `checkKeys`, when the next file lacks the TPM slot that opened, try the same factor once against the TPM slots the next file adds (in the next file, not in the file before). Accept only if one unwraps to the vault's data key (constant-time compare), then roll forward as for any kept slot. Passphrase slots keep `ErrChangeInterrupted` (P2-4g). A removed slot with no replacement this factor opens still opens nothing.

Stages and outcomes (integration owner: this package; the egress caller is unchanged):

| Stage | Drive holds | Factor | Outcome |
|---|---|---|---|
| Re-trust interrupted after the seal | file before | same PC, same PIN | opens, rolls forward |
| Re-trust interrupted after the seal | file after | same PC | opens, rolls forward |
| After roll-forward | file before put back | same PC | `ErrRolledBack` |
| Removal interrupted after the seal | file before | removed PC | `ErrNoSlotOpens`; passphrase rolls forward |
| Replaced by another PC, interrupted | file before | old PC | `ErrNoSlotOpens` |
| Re-trust interrupted, wrong PIN | file before | same PC | PIN error, one TPM failure, no second ask |
| Re-trust that changed the PIN, interrupted | file before | old or new PIN | fails closed, at most one extra TPM failure; passphrase recovers |

**Requirements:** CRED-8, CRED-9

**Acceptance tests:**
- CRED-8: `broker/vault/retrust_test.go::TestInterruptedSameHostRetrustRollsForward` — a same-PC re-trust crashed after the seal, with the file before or after on the drive, opens with that PC's factor, rolls forward, and the file before put back is refused. Catches the boot as an unknown host.
- CRED-9: `broker/vault/retrust_test.go::TestInterruptedRemovalStillRefusesTheRemovedHost` and `::TestReplacementByAnotherHostDoesNotOpen` — a removed PC, or one replaced by another PC, opens nothing mid-change. Catches a roll-forward that lets a removed slot return.
- CRED-8: `broker/vault/retrust_test.go::TestInterruptedRetrustWithPIN` — a wrong PIN still fails once; a changed PIN fails closed with at most one extra TPM failure. Catches a retry that doubles TPM lockout counts.

**Scope:** `broker/vault/keysbind.go`, `broker/vault/keyslot.go`, `broker/vault/*_test.go`, `broker/vault/ASSUMPTIONS.md`, this brief.

**Needs:** nothing. `broker/vault/` is in `tools/g1_scope.txt`; no open PR touches it (D-111).

**Usage estimate:** ~120k tokens.
