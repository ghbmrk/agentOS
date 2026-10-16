# APPROVAL-expiry-guard: check `expires` inside `answerLocked`

Work item: #1923 (release, tier A). Source: state-machine audit 2026-10-16 §2.2, R2a.

## Scope

`broker/owner/approvals.go` (`answerLocked` only), a new `broker/owner/expiryguard_test.go`, and one row in `broker/owner/ASSUMPTIONS.md`. Tier A: owner approvals gate spends and sends.

## Problem

`answerLocked` never compares the request's `expires` with `now`. It relies on every caller running `expireLocked` first (`channel.go` `route`, `local.go` `LocalAnswer`). Both do today, so the hole is latent, but a new caller that skips `expireLocked` accepts an expired code: an expired approval would authorize a spend or send (CH-10). On the local page the code-generator code is current, so nothing else stops it.

## Change

After `findLocked` returns a request, `answerLocked` expires it if `now` is not before `expires`: it is closed as `expired` (denied, kept for the digest through `addExpiredLocked`, its decisions appended to the caller's `decided`), and `findLocked` runs again, so the reply is the one for a request that is no longer open. For the existing callers this is a no-op, since they expired first.

**Acceptance tests:** CH-10: `TestAnswerRefusesAnExpiredRequestWithoutCallerExpiry` (`broker/owner/expiryguard_test.go`) calls `answerLocked` directly on a request past its expiry, without `expireLocked`, for a texted code and for the page's code-generator code; it must not accept, must close the request, and must record one expired denial. It fails without the guard.

Failure path: a caller that skips `expireLocked` approves a request after its code expired.

## Handoff and estimate

One session, under 60k tokens. L3 and Security reviews on the strongest model.
