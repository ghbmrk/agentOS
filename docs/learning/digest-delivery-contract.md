# Digest delivery contract

Normative for `broker/digestqueue` (W5-Da). Requirements: OP-1, OP-2. Wiring a sender is W5-Db/W5-Dc; nothing here sends a message.

## Why a separate queue

`modemlink.Link` keeps an in-memory queue and no persistent store, and its outage behaviour deliberately drops missed texts. Reusing its wire protocol does not make a digest durable. Digests therefore use a separate narrow notification class with a persisted boundary. Approval codes, stale decisions and third-party effects are never replayed through it.

Sources (`change.Pipeline.Digest`, `owner.Channel` notes) must offer a non-consuming `Peek` and an explicit `Ack` of one generation. A save-after-read reorder is insufficient.

## Guarantee

**The owner never loses a digest silently.** Every batch that admission accepted ends in exactly one of two kinds of state:

- `transport-accepted`: the transport reported acceptance.
- a state that is surfaced rather than dropped: `delivery-unknown`, `not-sent-exhausted`, `expired`, or a `Ready` batch past expiry whose sources were already consumed (reported by `Held`).

A source generation is acknowledged only after the batch that carries it is durable. A full or failing queue leaves the source pending and unacknowledged.

## Not guaranteed

- `delivery-unknown` means the text may have been delivered or not. Recovery never re-dispatches it. A later retry needs explicit not-sent evidence, so a duplicate or absent text is possible.
- `transport-accepted` is neither carrier delivery nor owner visibility. There is no exactly-once SMS promise.
- `Evidence` is an opaque, unauthenticated string recorded with the outcome.
- Status wording and the resolution path for surfaced states ship with the first sender (W5-Db/W5-Dc).

## State machine

`ready -> sending -> transport-accepted | delivery-unknown | not-sent-exhausted`; `ready -> expired` (only when no source was consumed); `ready -> cancelled` (Forget). A restart converts `sending` to `delivery-unknown` and persists that before use.

Crash-safe order: persist batch, then source `Ack`, then the batch's per-source acknowledgment bit, then `Begin`, which requires every bit set. A source ack retry is idempotent per source, generation and hash. `Acknowledge` is accepted only on a `Ready` batch and otherwise returns `ErrState` without touching the source. Compaction removes only terminal batches with all sources acknowledged, so an expired batch with an unconsumed source stays and blocks recovery rather than wedging the source silently. It keeps the dedupe ledger and sequence.

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
| D07 | Expiry: unacked batch never sent | `TestExpiryPreventsSending`, `TestExpiredUnacknowledgedBatchDoesNotConsumeSource` |
| D07 | Expiry with a consumed source is held, not dropped | `TestExpiredBatchWithConsumedSourceIsHeldNotDropped`, `TestCompactedExpiredBatchStillBlocksRatherThanWedgingSource` |
| D09 | Forget purges pending text, refuses in-flight | `TestForgetPurgesPendingPayload`, `TestForgetFailsBeforeMutatingAnyInFlightReference` |
| D11 | Compaction keeps dedupe and sequence; two stores reopen | `TestCompactionKeepsDedupeAndSequence`, `TestDistinctFileStoresRecoverAcrossBothReopens` |

Out of this slice (no owner, grants or sender wiring yet): D08 shared-ID collision and UNDO expiry, D10 clock restriction, quiet hours and approval priority, D12 migration from an old persisted format (the format is new here; old or malformed state fails closed, see `TestMalformedAndOldStateFailClosed`).
