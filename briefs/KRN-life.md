# KRN-life: a clerk key lives at most 30 days, and spend admission fails closed

Work items: #2670 item 1 (the first link's life cap) and #2613 items 8, 9, 11 and 12. Tier A. It follows KRN-ownerlink (#2686) on the same branch.

## Goal

1. **A first link lives at most `ClerkLife` once live.** A grant of a key whose earliest expiry is more than `ClerkLife` after it comes live (at + GrantHold), or that has no expiry, is refused (`ErrLife`). Failure path: a phone tap grants a clerk key that outlives D-146's 30-day renewal by Face ID.
2. **No spend while the log is broken (KRN-5, #2613 item 8).** `AdmitSpend` refuses with `log-broken` once a widening's anchor has failed. Failure path: a provider call goes out after a widening that nothing proved.
3. **Tests pin what reverts silently (#2613 items 9 and 12).** These cover a `Reserve` drop without its anchor, the cited-key check in `Extend`, and the liveness check in `Spend`.
4. **Simplicity (#2613 item 11).** `key.CheckChain`, a wrapper of `Chain`, is dropped. `Hold` reads the root instead of re-verifying the key. The stale `live` comment in `authorize.go` goes.

The slice harness renews its clerk key at the same limits before it lapses, so a run covers a history longer than one key's life. The browser and inbox fixtures grant their keys a hold before the test.

Out of scope: #2613 item 1 (spend reservations) and item 4 (it conflicts with MIG-4-spend-b1, as noted on #2613).

## Scope

`broker/kernel/`, `broker/clerk/inbox/` (test fixture and the slice harness), `broker/browser/` (test fixture), `briefs/KRN-life.md`.

**Guard files:** none (no new package).

## Acceptance tests

- D-146: `broker/kernel/grant_test.go::TestAClerkKeyLivesAtMostClerkLifeOnceLive`
- KRN-5: `broker/kernel/spend_test.go::TestAnUnanchoredReserveDropBreaksTheLogAndAdmitsNoSpend`
- LOG-7, KEY-6: `broker/kernel/spend_test.go::TestARevokedEnvelopeFundsNothingAndAPausedKeysPlanIsNotExtended`

## Estimate

About 80k tokens, single session.
