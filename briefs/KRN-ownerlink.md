# KRN-ownerlink: a passkey approves by narrowing the clerk's key

Work item: the owner's approval of an exact action (OWN-9), asked for by the browser lane (#2673, #2675). Tier A. It follows KRN-cosign (#2674).

## Goal

The owner's tap binds the exact approved action to the owner's device, so a compromised clerk cannot approve for itself, and the approval waits no hold:

1. **A passkey narrows a clerk key for its own holder.** A link after the first may be signed by an enrolled passkey instead of its parent's holder, only when it keeps that holder (`key.Narrow`). `Verified.ByOwner` marks such a tip. It hands out nothing the holder lacked, so it is no grant and waits no hold (D-146). Its caps count against the link alone, so a uses cap counts the approval. Failure path: a clerk derives its own "approval" and sends a logged-in submit the owner never saw.
2. **A link to another holder stays a grant.** Failure path: a stolen phone hands the clerk's power to an outside key at once, skipping the hold.
3. **A cut-off passkey's narrowings stop.** `Live`, shared by `Admit` and `clerk.Check`, refuses them. Failure path: an unenrolled phone keeps approving.
4. **A clerk can read the chain it checked.** `clerk.Verify` is `Check` returning the verified chain, opened in `core.txt`, so the browser gate requires `ByOwner` on the very chain `Check` verified against the full passkey set. Failure path: the gate re-verifies against the anchors alone and refuses every phone approval (#2675).

Out of scope: the browser gate requiring `ByOwner` and the tap signing the link (#2675), and the ceremony UX (#2643).

## Scope

`broker/kernel/`, `broker/clerk/clerk.go` and its test, `broker/core/core.txt` (one `open` line), `briefs/KRN-ownerlink.md`.

**Guard files:** none (no new package).

## Acceptance tests

- KEY-3, OWN-9, D-146: `broker/kernel/narrow_test.go::TestAPasskeyNarrowsAClerkKeyAtOnce`
- CLK-2, D-146: `broker/kernel/narrow_test.go::TestAPasskeysNarrowingKeepsItsHolderAndEndsAtCutOff`
- KEY-3: `broker/kernel/key/key_test.go::TestNarrowKeepsTheHolderAndNeverLoosens`
- CLK-2: `broker/clerk/clerk_test.go::TestClerkVerifyReturnsTheChainItChecked`

## Estimate

About 40k tokens, single session.
