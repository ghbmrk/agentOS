# CLK-run-open-wipe: a plaintext handed back with an Open error is wiped too

Board row: #5666 (tier A, lane:primary, class:release). Source: #5662's Findings line (CLK-run-mut-mail, #5324). Usage estimate: 40k tokens.

**Why (facts).** At 743d64d6, `loadReg` (`broker/clerk/run/gmailreg.go:47-51`) and `loadSeen` (`broker/clerk/run/seen.go:87-91`) return on an `Open` error before their `defer clear(plain)`. `aesSealer` returns nil plaintext with every error, so nothing leaks today; a sealer that fails after it decrypted (an AAD or freshness check after decryption, as a TPM-backed STO-4 sealer might) would hand back the registration's client secret, or the read-mail record, and the caller would leave it unwiped.

## Requirement
- **Invariant (#5362, #5662):** every plaintext a `clerk.Sealer` hands back is wiped once the caller is done with it, read through `gmailtest.Kept`.

## Design
Defer the clear before the error check in both loaders; `clear(nil)` is a no-op, so the success path and nil-plaintext errors are unchanged.

## Scope (files)
- In scope: `broker/clerk/run/gmailreg.go`, `seen.go`, their tests (`gmailreg_test.go`, `gmailsignin_test.go`), this brief.
- Out of scope: `broker/clerk/run/senders.go`, which has the same gap (release finding raised on the PR).

## Acceptance tests
**Acceptance tests:** `TestAFailedOpenLoadsNoRegistration` (`gmailreg_test.go`) and `TestAFailedOpenLoadsNoSeenRecord` (`gmailsignin_test.go`): with `gmailtest.Kept{OpenErr: ...}`, the load returns nothing and `k.Wiped()` reads one plaintext, wiped.
