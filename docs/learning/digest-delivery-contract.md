# Digest delivery contract

Normative for `broker/digestqueue` (W5-Da, W5-Db). Requirements: OP-1, OP-2. W5-Db adds the sender contract and `modemlink.Link.SendReceipt`; wiring them into agentosd is W5-Dc, so nothing here sends a message yet.

## Why a separate queue

`modemlink.Link` keeps an in-memory queue and no persistent store, and its outage behaviour deliberately drops missed texts. Reusing its wire protocol does not make a digest durable. Digests therefore use a separate narrow notification class with a persisted boundary. Approval codes, stale decisions and third-party effects are never replayed through it.

Sources (`change.Pipeline.Digest`, `owner.Channel` notes) must offer a non-consuming `Peek` and an explicit `Ack` of one generation. A save-after-read reorder is insufficient.

## The gate (W5-Db)

`begin` is the single gate. Every owner-facing text that carries queued digest content is sent only by `digestqueue.Sender.Send`, only after `begin` has persisted `sending` for that batch, and only with text rendered from the batch `begin` returned. `Send` calls `Transport.Deliver` exactly once and records the result with `finish` for that attempt. The rule is structural: `begin` and `finish` are unexported, and `TestOnlySenderSendCallsDeliver` fails if any other code in the package names `Deliver`, `begin` or `finish`. Any pre-send check runs before `Send`, so a refusal never begins an attempt. One named exception, provisional until Mark rules on SG-3: the fixed queue-outage line (W5-Dc DC-8), which carries no queued content.

`Send` records `delivery-unknown` for a transport panic, a context that ended during the call, a missing receipt, an outcome it does not know, or a receipt without valid evidence. A render failure, an empty rendering or a render panic never reaches the transport and is recorded as `proven-not-sent` (`render-failed`), which consumes one attempt. If `finish` cannot persist, `Send` returns `delivery-unknown` with the error and the queue is quarantined; reopening turns the attempt unknown, so it is never resent.

`SendReceipt` reports `not-sent` only when the bridge never took the text: refused before queuing, timed out while still queued (checked under the link's lock), or answered `CodeRecipient`, which the bridge emits only before any modem call (pinned by `TestRecipientCodeOnlyBeforeModemSend`). `accepted` needs `CodeOK`. Every other case is `unknown`.

## Decisions (W5-Db)

- **Tier.** `digestqueue` is tier A: it decides whether an outbound owner text happens and holds the never-resend-unknown rule.
- **Held batch** (ready, past expiry, some source consumed). `recover` finishes its remaining acknowledgments, so one resolution covers every line. `Late(id, now, expires)` re-arms it once: only when `Held(now)` reports it, every source is acknowledged and `Late` is unset. It sets `Late` and the new expiry, persists, and `begin` gates it as usual; the render func sees `Batch.Late` and adds the late header (wording: W5-Dc). A late batch held again stays held. `begin`'s expiry check is never relaxed.
- **Forget per snapshot.** On a `Ready` (held included) or `Expired` batch, `Forget` removes only the snapshots whose references hold the reference, with their acknowledgment bits. A batch left empty is cancelled (from `Ready`) or stays expired, and is redacted. Accepted, failed and cancelled batches are redacted whole. A matching `sending` or `delivery-unknown` batch refuses the whole call before any mutation.
- **Expired batch.** Its intent ended with nothing consumed and nothing sent, so the source re-offers it: `recover` skips expired batches, `Enqueue` admits the same source, generation and hash again as a new `Ready` batch when the ledger's batch is expired (and still holds that snapshot), and `Compact` drops an expired batch once no ledger entry points to it. Against any batch that is not expired, the same parameters return the existing batch and a different hash is `ErrConflict`, as before.

**Source-side forget duty** (for DIG-1 and W5-Dc's sources). A source that holds a forgotten reference drops it and never offers again a generation that contained it; if lines remain pending it offers a higher generation without the reference. A forgotten generation re-offered is refused with `ErrConflict`, so `Collect` fails visibly until the source has done so.

## Guarantee

**The owner never loses a digest silently.** Every batch that admission accepted ends in exactly one of two kinds of state:

- `transport-accepted`: the transport reported acceptance.
- a state that is surfaced rather than dropped: `delivery-unknown`, `not-sent-exhausted`, a `Ready` batch past expiry whose sources were already consumed (reported by `Held`, re-armed once by `Late`), or `expired`, whose lines the sources re-offer into a new batch.

A source generation is acknowledged only after the batch that carries it is durable. A full or failing queue leaves the source pending and unacknowledged.

## Not guaranteed

- `delivery-unknown` means the text may have been delivered or not. Recovery never re-dispatches it. A later retry needs explicit not-sent evidence, so a duplicate or absent text is possible.
- `transport-accepted` is neither carrier delivery nor owner visibility. There is no exactly-once SMS promise.
- `Evidence` is an opaque, unauthenticated string recorded with the outcome.
- Status wording and the owner-visible resolution of each surfaced state ship with W5-Dc; the table is in [briefs/W5-Db.md](../../briefs/W5-Db.md#decisions-on-the-folded-rows).

## State machine

`ready -> sending -> transport-accepted | delivery-unknown | not-sent-exhausted`; `ready -> expired` (only when no source was consumed); `ready -> ready (Late)` (a held batch re-armed once); `ready -> cancelled` (Forget removed its last snapshot). A restart converts `sending` to `delivery-unknown` and persists that before use.

Crash-safe order: persist batch, then source `Ack`, then the batch's per-source acknowledgment bit, then `begin`, which requires every bit set. A source ack retry is idempotent per source, generation and hash. `Acknowledge` is accepted only on a `Ready` batch and otherwise returns `ErrState` without touching the source. Compaction removes terminal batches with all sources acknowledged, and expired batches no ledger entry points to (superseded by a re-offer). It keeps the dedupe ledger and sequence.

Bounds: `MaxBatches`, `MaxSources`, `MaxAttempts`, `MaxBytes`. Reaching one fails closed with `ErrFull` and loses nothing.

## Clause-to-test map

Package `broker/digestqueue`. Oracle IDs D01-D12 are the original crash oracles.

| Clause | Behaviour | Test |
|---|---|---|
| D01 | Failure before batch persist: source unchanged, no batch | `TestAdmissionFailureNeverCallsSourceAck`, `TestSaveFailureNeverReturnsQueueAdmission` |
| D02 | Save/fsync error: restart sees old valid state | `TestPostCommitErrorQuarantinesUntilDurableReopen`, `TestRestartRecoverySaveFailureRefusesOpen`, `TestMalformedAndOldStateFailClosed` |
| D03 | Crash after persist, before ack: one batch, ack on replay | `TestRestartAfterSourceAckBeforeQueueBitmapSave`, `TestPartialAcknowledgmentRecoveredBeforeNewPeek`, `TestCollectionDurablyQueuesBeforeAcknowledging` |
| D03 | Duplicate acknowledgment is idempotent | `TestDuplicateAcknowledgmentIsIdempotent` |
| D03 | Acknowledge outside `Ready` refused, source untouched | `TestAcknowledgeRefusedOutsideReadyLeavesSourceUntouched` |
| D04 | Newer generation survives an older ack | `TestNewerGenerationSurvivesOlderRecoveryAck`, `TestNewGenerationDoesNotChangeOlderAcknowledgment` |
| D05 | Concurrent collectors: one batch per generation | `TestConcurrentCollectorsOnOneCoordinatorDoNotDuplicate`, `TestConcurrentCollectionCreatesOneBatch` |
| D06 | Crash while sending: unknown, never re-dispatched | `TestRestartOfSendingIsUnknownAndNeverRedispatched`, `TestUnknownRequiresExplicitNotSentEvidenceBeforeRetry` |
| D06 | Accepted is terminal and claims no visibility | `TestAcceptedIsTerminalAndDoesNotClaimVisibility`, `TestRetryLimitPersists` |
| D07 | Bound reached: new source stays unacknowledged | `TestCapacityLeavesNewSourcesUnacknowledged`, `TestFullQueueLeavesSourcePendingUnacknowledged`, `TestByteLimit`, `TestSourceLedgerBound` |
| D07 | Expiry: unacked batch never sent | `TestExpiryPreventsSending` |
| D07 | Expiry with a consumed source is held, not dropped | `TestExpiredBatchWithConsumedSourceIsHeldNotDropped` |
| D09 | Forget purges pending text, refuses in-flight | `TestForgetPurgesPendingPayload`, `TestForgetFailsBeforeMutatingAnyInFlightReference` |
| D11 | Compaction keeps dedupe and sequence; two stores reopen | `TestCompactionKeepsDedupeAndSequence`, `TestDistinctFileStoresRecoverAcrossBothReopens` |
| DB-1 | `digestqueue` is tier A | `tests/test_risk_tier.py` `test_paths` |
| DB-2 | Refusals never call the transport | `TestSenderRefusalNeverCallsTransport`, `TestSenderBeginSaveFailureDoesNotCallTransport`, `TestSenderCancelledAndNilContextsDoNotBegin` |
| DB-2 | Panic, cancel, missing or bad receipt is unknown, never resent | `TestSenderTransportPanicOrCancelIsUnknown`, `TestSenderFinishFailureReopensUnknownNotResent`, `TestConcurrentSendsDeliverOnce` |
| DB-2 | Render sees only the begun batch; render failure is not sent | `TestSenderRendersOnlyBegunBatch`, `TestSenderRenderFailureIsNotSentWithoutTransport`, `TestSenderNotSentRetriesWithinLimitThenExhausts`, `TestNewSenderRequiresEveryPart` |
| DB-2 | The gate is structural | `TestOnlySenderSendCallsDeliver` |
| DB-3 | Receipt: accepted, not sent, unknown | `TestSendReceiptOKCarriesID`, `TestSendReceiptRefusedBeforeQueueIsNotSent`, `TestSendReceiptTimeoutBeforeHandIsNotSent`, `TestSendReceiptTimeoutAfterHandIsUnknown`, `TestSendReceiptRecipientIsNotSent`, `TestSendReceiptOtherCodesAreUnknown`, `TestRecipientCodeOnlyBeforeModemSend` (`broker/modemlink`) |
| DB-4 | Held batch finished by recover, re-armed late once | `TestRecoverFinishesHeldBatch`, `TestLateRearmsHeldOnce`, `TestLateRefusedOnFreshOrLateBatch` |
| DB-5 | Forget removes only matching snapshots | `TestForgetRemovesOnlyMatchingSnapshots`, `TestForgetKeepsUnaffectedSourceCollectable`, `TestForgetLastSnapshotCancels`, `TestForgottenGenerationNeverReadmitted`, `TestForgetInFlightRefusesBeforeMutation` |
| DB-6 | Expired generation re-offered; live batches keep OP-1 | `TestExpiredGenerationReofferedInNewBatch`, `TestRecoverSkipsExpired`, `TestCompactDropsSupersededExpired`, `TestSameParamsNonExpiredStillIdempotent`, `TestRepeatedExpiryReoffersAgain` |

Out of this slice (no owner, grants or sender wiring yet): D08 shared-ID collision and UNDO expiry, D10 clock restriction, quiet hours and approval priority, D12 migration from an old persisted format (the format is new here; old or malformed state fails closed, see `TestMalformedAndOldStateFailClosed`).
