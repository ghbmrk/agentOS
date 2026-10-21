# KRN-passkey: the passkey holds the root, clerk keys are bounded, grants wait

Work items: D-145 (#2631 item 3, "Require a limit") and D-146 items 1 to 4 ("Limit the clerk" and the hardware-key plan Mark approved 2026-10-21). Tier A. Item 5 of D-146 (the second passkey for big widenings and big one-offs, plus the owner-settable line) is the next PR.

## Goal

Full power stays with the owner's passkeys, and a hacked core can act only within capped, lapsing keys that the owner sees granted and can cancel. Each rule sits at its enforcement point and fails closed:

1. **The root is the passkey's.** `Root` has no separate holder, because its holder is its owner. Only a passkey signature uses a bare root (a one-off over the clerk's limits) or derives from it. Failure path: the home clerk signs plans with full power.
2. **Keys off the root lapse and are capped.** The chain check refuses a first link that lacks an expiry and a daily spend cap. `key.ClerkKey` builds one with a life of 30 days. Failure path: a leaked clerk key works forever, without limit.
3. **Hardware-key anchors.** The kernel and every clerk trust the anchors given at boot. A phone passkey counts only through an anchor's signed enrollment, and a revoke is final. Failure path: a cloud account, or a lost phone, becomes the root.
4. **Grants wait.** Roots and first links are logged grants, which `Issue` takes in one batch. A grant is live after `GrantHold` on the judging party's own clock, and a revoke cancels it; `State.Pending` lists what is waiting. A renewal at the same limits is live at once. Failure path: a tricked tap widens authority with no window for the owner to notice.
5. **SPEC** KEY-4, KEY-5 (D-141's standing key), ID-1 and REC-3 are updated to match (an L1 spec diff).

Out of scope: co-signing big widenings (next PR), the owner notice and the passkey ceremony (the owner channel, #2643), and revoking an anchor (REC-3's re-root).

## Scope

`broker/kernel/`, `broker/clerk/`, `briefs/KRN-passkey.md`, `DECISIONS.md` (D-145, D-146), `SPEC.md`.

**Guard files:** none (no new package).

## Acceptance tests

- KEY-3, KEY-4, D-145, D-146: `broker/kernel/key/key_test.go::TestKeyOffTheRootLapsesAndIsCapped`, `::TestBareRootIsThePasskeysAlone`, `::TestPasskeysAreTheAnchorsAndWhatTheyEnroll`
- KEY-1, KEY-4, KEY-6, CLK-2, KRN-7: `broker/kernel/grant_test.go`, every test
- EVL-1: `broker/kernel/sim/sim_test.go::TestSweepHoldsInvariants` and `::TestMutantsAreCaught`, with grants, renewals and a home clerk signing under a bare root

## Estimate

About 150k tokens, single session.
