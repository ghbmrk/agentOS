# KRN-grantcheck: check a grant when it is staged

Work item: #2742 (item 6, clerk step). Tier A.

## Goal

A malformed refresh grant is caught only at `Exit.Reconnect`, after the owner's tap and the hold, and then reads as `credential`. Failure path: the owner signs in, the owner side stages a grant with a missing or unknown field, the owner taps and waits out the hold, and the reconnect step fails with no sign of why. Fix: export `Exit.CheckGrant`, the same refusal `Reconnect` makes (a refresh clerk, and a grant `readGrant` accepts) without the write. `Reconnect` calls it, so the two never differ. The host lane calls it at stage.

## Scope

- `broker/clerk/exit.go`, `oauth_test.go` and `ASSUMPTIONS.md`.
- `briefs/KRN-grantcheck.md`.

**Guard files:** none.

## Acceptance tests

- CLK-1: `broker/clerk/oauth_test.go::TestCheckGrantMatchesReconnect`.

## Estimate

About 5k tokens, single session.
