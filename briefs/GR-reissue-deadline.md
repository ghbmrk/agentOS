# GR-reissue-deadline: a restart re-issue keeps its absolute deadline

Work item: #1317 (release, tier A). Source: GR10 restart re-issue.

## Scope

`broker/grants/gate.go` (the `Owner` interface and `flush`, plus a `closeExpired` helper), `broker/owner/approvals.go` (`ErrExpired`, `RequestEach`, `RequestLocalEach`, `openLocked`), the two boot calls in `broker/owner/channel.go`, the test fakes and callers that implement or call those methods (`broker/grants/rig_test.go`, `broker/mail/gate_test.go`, `broker/cmd/agentosd/mail_test.go`, `broker/vm/gvisor/corpus_test.go`, `broker/owner/localapprove_test.go`, `broker/owner/repeat_test.go`, `broker/owner/review_test.go`), two new test files `broker/owner/reissuedeadline_test.go` and `broker/grants/reissuedeadline_test.go`, and rows GR10 and O7 in the packages' `ASSUMPTIONS.md`. Tier A: owner approvals gate spends and sends.

## Problem

`flush` re-issues held intents after a restart. It computed each item's remaining TTL from one `now`, then sent the texted re-issues (`RequestEach`, a slow carrier send) before the page ones (`RequestLocalEach`). The owner channel opened each request at its own later `now` plus that TTL, so the expiry slid later by however long the earlier send took. A page intent whose deadline passed during the send was still opened, with a fresh expiry, and could be approved after its original deadline (CH-10, OP-4).

## Change

`RequestEach` and `RequestLocalEach` take one absolute deadline per item; zero means a fresh request with the default expiry. `openLocked` opens a request with that exact deadline (still capped by `MaxTTL` and the low-tier code TTL) and refuses one whose deadline has passed with `ErrExpired`: no request, no text, no pending entry. `flush` passes each re-issued item's original expiry, closes an intent the owner refused as expired, and also closes a re-issued intent whose expiry passed while a failed send was outstanding, both with the "expired" reason. Final approval needs no new check: every owner answer path runs `expireLocked` before deciding, so a code answered past the exact deadline is decided as expired.

**Acceptance tests:** CH-10, OP-4: `TestAReissuedRequestKeepsItsDeadline` and `TestAPassedDeadlineIsRefusedNotRenewed` (`broker/owner/reissuedeadline_test.go`) open texted and page requests under a deadline after the clock advanced and check the exact expiry, the default for a zero deadline, an expired decision for a YES past the deadline, and `ErrExpired` with nothing opened for a passed deadline. `TestASlowTextSendCrossingTheDeadlineClosesThePageIntent` and `TestAReissuedPageIntentKeepsItsDeadline` (`broker/grants/reissuedeadline_test.go`) check that `flush` passes the original deadline for both kinds and that a texted send outlasting it closes the page intent as expired instead of asking it.

Failure path: a slow re-issued text send carries a page intent past its deadline, and the owner approves it on the page under a renewed expiry.

## Handoff and estimate

One session, under 100k tokens. L3 and Security reviews on the strongest model.
