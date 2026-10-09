# W5-Dc-r7: A forget reaches a digest batch whose delivery is unknown (CAP-3)

Release finding on #592 (W5-Dc, merged a818e20): the builder's own finding, also raised by reviewer 6079804454, who suggested redacting an Unknown batch's snapshots while keeping its state and evidence. BOARD row W5-Dc-r7.

SPEC rows: CAP-3 (a deletion propagates: the record and everything derived from it leave recall at once; actions already taken stay done), OP-9 and CH-15 (the digest status line stays true).

**Why one package.** One question, one seam: what `Queue.Forget` does to a batch in state Unknown. The answer touches `Forget`, `validate` and `finish` in `broker/digestqueue/queue.go` and a comment and tests in `broker/cmd/agentosd/digest.go`. About 150 to 200 lines with tests.

**Order.** Independent of W5-Dc-r1. W5-Dc-r9 (Unknown and held batches count against `MaxBatches`) also changes how Unknown batches are kept in `queue.go`: whichever of r7 and r9 merges second merges main first and reruns both packages' tests. W5-Dc-r12 (forget double fault) touches the agentosd forget path (`forget.go`, `digest.go` `forget`): same rule. Line references are from main at a818e20; reread them there.

**Conflict risk with held Codex drafts (CODEX-1).** Open, unmerged W5-D PRs held as Codex drafts (for example #335, branch `pkg/w5-d37-durable-shared-pacing-codex-20261008`) edit `broker/digestqueue/queue.go` and `collector.go` on a base older than #555. Build from main only; do not read or depend on those branches. Keep the change inside the functions named here so a later rebase on their side stays small.

**Today.**
- `Forget` (queue.go:610) prechecks every batch. If any batch holding the reference is `Sending` or `Unknown` it returns `ErrInFlight` and changes nothing.
- An Unknown batch never leaves Unknown: `begin` (queue.go:444) refuses anything but `Ready`, nothing resends it (DB contract: "Unknown/in-flight deliveries remain unresolved regardless of expiry and never become eligible for automatic retry", `Expire` comment), and `Compact` (queue.go:666) drops only terminal batches. `New` turns a `Sending` batch left by a crash into Unknown (around queue.go:195).
- So a forget of a reference held by an Unknown batch is refused for ever. agentosd's `forget` (digest.go:568) holds the reference in `forgets`, saves, and returns the error; `ownerForget` keeps the forget owed and retries without end, and the done text never goes (digestqueue ASSUMPTIONS lines 151 to 162).
- The modem side keeps no copy: `modemlink.SendReceipt` (modemlink.go:274) drops the item on timeout both before and after hand. A text already handed to the modem is beyond the box's reach.
- The status line (`digestUnknownStatus`, digest.go:57), the next digest's line about it (`digestUnknownLine`, digest.go:50) and `statusSource.Peek` read only `State`, `Created` and `ID`, never `Snapshots`.

**Decision: redact the Unknown batch whole, keep its state.** CAP-3 supports this reading; record it as an assumption in digestqueue ASSUMPTIONS (UF-3).
- CAP-3 says the derived copy leaves recall at once. An Unknown batch's snapshots are a derived copy that nothing will ever render again: the batch is never resent. Keeping them serves no requirement; refusing the forget breaks CAP-3.
- CAP-3 also says actions already taken stay done. The text may have reached the owner; that is an action already taken, and redaction does not pretend otherwise.
- Keeping `State == Unknown` keeps OP-9 and CH-15 true: the status line still says a digest may not have arrived, and the next digest still names that day.
- Rejected:
  - Keep refusing: CAP-3 is never met and the forget is owed for ever.
  - Move the batch to `Cancelled` or another terminal state: it says the digest was not sent, which may be false (CH-12), and the status line is lost.
  - Delete the batch: it loses the status line and evidence, and breaks the source ledger's `Latest` pointer (`Enqueue` returns `ErrRetired` when the latest batch is missing).
  - Drop only the matching snapshots, as for `Ready`: the rest of the batch is never rendered again either, so keeping it buys nothing and needs a new partial-redaction state. Whole redaction is what terminal batches already get.
- `Sending` keeps returning `ErrInFlight`. That refusal is bounded: `Sender.Send` calls `finish` within the transport's wait, and a crash turns `Sending` into Unknown on reopen, which this package now redacts. The existing owed-forget retry covers it.

**Requirements** (local IDs under CAP-3):
- **UF-1, forget redacts an Unknown batch.** `Forget` treats a batch in state `Unknown` that holds the reference like a terminal batch: `Snapshots = nil`, `Acknowledged = nil`, `Redacted = true`. `State`, `Attempts`, `Evidence`, `Created`, `Expires`, `Late` and the source ledger stay. The precheck still refuses without any change when a `Sending` batch holds the reference, even if an Unknown batch holds it too (all or nothing, as today).
- **UF-2, the redacted Unknown batch is valid and stays put.**
  - `validate` (queue.go:206) admits `Redacted` for state Unknown as well as terminal states, still with no snapshots and no acknowledgments.
  - `finish` refuses a redacted batch with `ErrState` before any change, so it can never return to `Ready` (NotSent) with no snapshots, nor commit a state `validate` rejects. `begin` already refuses `Redacted`; keep it.
  - `Compact` keeps the batch (it is not terminal), so the status line and the ledger's `Latest` pointer stay. Bounding how long Unknown batches are kept is W5-Dc-r9's, not this package's.
  - `Enqueue` already skips redacted batches when deduplicating, so an identical re-offer of the forgotten generation is `ErrConflict`. That is the existing source duty (digestqueue ASSUMPTIONS line 108: never re-offer a generation containing a forgotten reference); keep it and say so in ASSUMPTIONS. Source-side forget across sources is W5-Dc-r5.
  - Reopen: a redacted Unknown batch saved to disk reopens unchanged through `New` and `validate`.
- **UF-3, the forget completes in agentosd.** A forget of a reference that only an Unknown batch holds returns nil from `digest.forget`, drops it from `forgets`, and lets `ownerForget` send its done text. The status line for that day is unchanged. Update the `forget` comment (digest.go:564 to 567) and digestqueue ASSUMPTIONS lines 67 to 75 and 151 to 153: `ErrInFlight` now means a `Sending` batch only. Add an assumption there: redacting an Unknown batch whole while keeping its state is a reading CAP-3 supports, not one SPEC states.

**Failing-test-first controls.** Each must be shown failing at main, with the failing message cited in the PR, then passing at the head. Queue tests go in `broker/digestqueue/resolve_test.go` (or a new `forget_unknown_test.go`); agentosd tests in `broker/cmd/agentosd/digest_test.go`. Markers: `REQ: CAP-3 (W5-Dc-r7 UF-1)` and so on.

| ID | Test | Why it fails on main |
|---|---|---|
| UF-1 | `TestForgetRedactsAnUnknownBatch`: enqueue two snapshots, `begin`, `finish(OutcomeUnknown)`, `Forget` one reference. The batch is `Unknown`, `Redacted`, with no snapshots or acks, the same `Attempts` and `Created`; the forgotten line is nowhere in the store bytes (`st.Load`). | `ErrInFlight`. |
| UF-1 | `TestForgetStillRefusesWhileSending`: one `Sending` and one Unknown batch hold the reference; `Forget` returns `ErrInFlight` and the store bytes are unchanged. | Passes on main; it pins the all-or-nothing precheck. Show the mutant "skip Sending in the precheck" failing it. |
| UF-1 | Change `TestForgetInFlightRefusesBeforeMutation` (resolve_test.go:280) so its in-flight batch is `Sending`, not Unknown. Keep `TestForgetFailsBeforeMutatingAnyInFlightReference` (queue_test.go:404), which already uses `Sending`. | The old expectation (Unknown refuses) is what this package changes; cite it in the PR. |
| UF-2 | `TestRedactedUnknownSurvivesReopenAndCompact`: after UF-1's forget, `Compact`, then reopen with `New`: the batch is still there, Unknown and redacted, and `validate` accepts it. | `ErrInFlight` before any of it. |
| UF-2 | `TestFinishRefusesARedactedUnknownBatch`: after UF-1's forget, `finish` with the batch's attempt and each of `NotSent`, `OutcomeUnknown` and `TransportAccepted` returns `ErrState` and changes nothing; the queue is not broken. | `ErrInFlight` before any of it. Refusing all three outcomes is the intended rule; the mutant check applies to `NotSent` only: show the mutant "no Redacted check in finish" failing on `NotSent` (it revives an empty batch, which `commit` refuses). |
| UF-2 | `TestReofferOfARedactedUnknownGenerationConflicts`: after UF-1's forget, `Enqueue` of the same source and generation is `ErrConflict`; a higher generation is admitted. | `ErrInFlight` before any of it. |
| UF-3 | `TestDigestForgetOfAnUnknownDigestCompletes`: in the digest rig, the transport answers `OutcomeUnknown`, `r.at(0, 8, 0)`; `r.d.forget("owner:a")` returns nil; `forgets` is empty after a reboot; no batch holds a snapshot with the reference; the STATUS line still reads `digestUnknownStatus` and the next digest still carries `digestUnknownLine` for that day. | `ErrInFlight`. |
| UF-3 | Update the existing tests that expect `ErrInFlight` from an Unknown batch (digest_test.go:386, 489, 497, 549): `TestDigestForgetReachesTheQueue` now expects nil, and the refused-forget hold tests (`TestDigestRefusedForgetHoldsItsReadyBatchAfterARestart` and the test at line 549) keep testing the hold through the injected refusal (`r.f.digest`, as at line 568) or a `Sending` batch. Every hold behaviour they pin must still be pinned. | They pin today's refusal. |

**Controls that must keep passing.** All `broker/digestqueue` and `broker/cmd/agentosd` tests, in particular `TestForgetPurgesPendingPayload`, `TestForgetRemovesOnlyMatchingSnapshots`, `TestForgetKeepsUnaffectedSourceCollectable`, `TestForgetLastSnapshotCancels`, `TestDigestForgetBeforeOpenPurgesOnOpen`, `TestDigestForgetBeforeOpenSurvivesARestart`, and the Unknown status-line tests from W5-Dc.

**Threat check for the reviewer.**
- No path renders, sends or logs a redacted batch's text: trace `begin`, `Sender.Send`, `render`, `Late`, `Held`, `Collector.recover` and the status sources with a redacted Unknown batch present.
- A redacted Unknown batch cannot return to `Ready` or be resent by any path, including reopen after a crash and a stale `finish`.
- The forget is all or nothing: a `Sending` holder still refuses before any change, and the store bytes show it.
- No text claims the digest was or was not delivered beyond what is known (CH-12): the status line and the next digest's line are unchanged.
- The queue cannot be marked broken by the new state: `validate` and `commit` accept everything `Forget` writes.

**Out of scope.**
- How long Unknown batches are kept and `MaxBatches` (W5-Dc-r9).
- Source-side forget across sources and the re-offer rule (W5-Dc-r5).
- The forget double fault and tombstone replay (W5-Dc-r12).
- Copies outside the queue (modem, carrier, the owner's phone): actions already taken stay done (CAP-3).

**Scope:**
- `broker/digestqueue/queue.go` (`Forget`, `validate`, `finish` only), `broker/digestqueue/resolve_test.go` or a new `broker/digestqueue/forget_unknown_test.go`, `broker/digestqueue/queue_test.go` if a control moves.
- `broker/digestqueue/ASSUMPTIONS.md`: the Forget paragraph (lines 67 to 75) and the agentosd Forget note (lines 151 to 162).
- `broker/cmd/agentosd/digest.go` (the `forget` comment only), `broker/cmd/agentosd/digest_test.go`.
- `briefs/W5-Dc-r7.md` (Delivery notes only), `BOARD.md` row W5-Dc-r7.

**Needs:** W5-Dc (merged, #592).

**Done:**
- CI green.
- UF-1, UF-2 and UF-3 covered by passing tests with markers.
- Risk tier A (`broker/digestqueue`, `broker/cmd`).

## Delivery

Builder model: strongest model (risk tier A; the Sonnet pilot covers tiers B and C only). One package per session, tests first: land each test red at main before the fix, and keep the message for the PR. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening the PR. Review: L3 on the strongest model with the threat check above, then a separate Security section (OPERATING §3–4); the CAP-3 path is security-critical. Estimate/checkpoint: about 60k tokens, not a ceiling (OPERATING §5).
