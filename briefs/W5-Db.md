# W5-Db and W5-Dc: digest sender contract, then its wiring into agentosd

Board section: Integration: wiring merged packages into the box. Folds BOARD release rows W5-Da-r1 to r4 (lens and L3 on #555).

W5-Da (#555, a41c68d) merged `broker/digestqueue` and `docs/learning/digest-delivery-contract.md`: a durable queue and collector that never send. These two packages make it send. **W5-Db** finishes the sender contract below agentosd: the one send path, the transport's classified receipt, and how held, expired and forgotten batches end. **W5-Dc** wires it into agentosd: storage, the daily send, STATUS lines and the forget hook. DIG-1 then adapts the `Digest()` sources (`digestSources` in `cmd/agentosd/capoff.go`, `change.Pipeline.Digest`, `owner.Channel.TakeDigestNotes`) into `digestqueue.Source`; it reads the contract and does not edit `broker/digestqueue`.

Read first: CLAUDE.md, the contract doc, `broker/digestqueue/ASSUMPTIONS.md` (sections "Persistence and transition behavior" and "Remaining integration packages"), and `queue.go`/`collector.go` (about 800 lines).

## Design rule: `Begin` is the single gate

Agreed with the second coordinator (session_01UQZkdkzP8Xm93fkbmuv81p). Every owner-facing text that carries queued digest content is sent only by `digestqueue.Sender`, only after `begin` has persisted `sending` for that batch, and only with text rendered from the batch `begin` returned. Nothing else sends digest content: not a source, not DIG-1, not a STATUS path, not a retry loop. A text that reports on the digest itself (a delivery-unknown or held notice) reaches the owner as a line in a later batch, through the same gate, or on STATUS, which the owner pulls. Any pre-send check (W5-Dc's) runs before `Sender.Send`; a refusal never reaches `begin`, so no attempt is left to finish.

The gate is structural, not a convention. W5-Db unexports `Begin` and `Finish` (`begin`, `finish`), so `Sender` is their only caller and the compiler enforces it; a package test asserts no exported function but `Sender.Send` calls `Transport.Deliver`. W5-Dc's gate test scans every non-test `.go` file under `broker/` (DC-6).

One named exception, provisional until Mark rules on SG-3: the fixed queue-outage line (DC-8). It carries no queued content, so no batch, attempt or ledger state can be wrong about it.

## Decisions on the folded rows

- **r3, tier.** `digestqueue` joins `TIER_A_BROKER` in W5-Db's first commit. Reason: once `Begin` is the single gate, the package decides whether an outbound text to the owner happens and holds the rule that an unknown send is never repeated (OP-2). OPERATING §3 puts a package that gates effects in tier A, in the PR that makes it one. Its callers (`cmd`, `owner`, `modemlink`) are tier A already, so the move adds Security review of the gate itself, not of new paths.
- **r4, held batch** (ready, past expiry, some source consumed). `Collector.recover` *may finish* a held batch: it keeps acknowledging the batch's remaining sources, as today, so every line the batch carries is consumed in one place and one resolution covers it. Say so in the `recover` comment and the contract. Then the batch is resolved by **sending it late, once**: `Queue.Late(id, now, expires)` re-arms a batch that `Held(now)` reports with every source acknowledged and `Late` unset. It sets `Late` and the new expiry, persists, and `begin` then gates it as usual. The rendered text starts with the late header (wording per r1). A late batch held again stays held: it is not re-armed, and W5-Dc surfaces it (r1). Never relax `begin`'s expiry check.
- **r2, forgotten source generation.** Today `Forget` purges a whole matching batch and sets `Acknowledged` to nil. An unaffected source's unacknowledged generation then stays pending at the source, while the ledger still holds it, so every later `Collect` fails with `ErrConflict` (or `ErrRetired` after `Compact`), and an unaffected consumed line is lost without a word. New rule: on a `Ready` (held included) or `Expired` batch, `Forget` removes only the snapshots whose `References` hold the reference, with their acknowledgment bits. A batch left with no snapshot becomes `Cancelled` (from `Ready`) and redacted. `Accepted` and `Failed` batches are redacted whole, as today. `Sending` and `Unknown` still refuse the whole call with `ErrInFlight` before any mutation. Source side (contract text, for DIG-1 and W5-Dc's sources): a source that holds a forgotten reference drops it and never offers again a generation that contained it. If lines remain pending, it offers a higher generation without the reference. Until it has done so, `Collect` fails visibly (W5-Dc's STATUS line), never silently.
- **Expired batch** (no source consumed; contract's "blocks recovery"). Blocking forever is a wedge, not a surface. OP-1 still holds: the expired batch's intent ended at expiry with nothing consumed and nothing sent (`begin` refuses an expired batch), so re-admitting the same parameters starts a new intent rather than replaying the old one; against any non-`Expired` batch the same source, generation and hash still return the existing batch and a different hash is still `ErrConflict`. New rule: `recover` skips `Expired` batches. `Enqueue` admits the same source, generation and hash again when the ledger's batch for it is `Expired`, repoints the ledger and creates a new `Ready` batch (the dedupe-by-body path must not return the expired batch). `Compact` may drop an `Expired` batch once no ledger entry points to it. The lines then go out in the next digest; the missed digest itself is the owner's signal (CH-15).
- **r1, status wording and resolution per surfaced state.** Owned by W5-Dc. SPEC fixes what each state must do (CH-15, OP-2, OP-9); the exact words are the builder's, reviewed by the UX lens and checked by `ownerWorded`, in one table.

| State | Resolution | Owner sees |
|---|---|---|
| `delivery-unknown` | never resent (OP-2) | one line in the next accepted digest, and a STATUS line until that digest is `transport-accepted` |
| `not-sent-exhausted` | not resent | same as unknown |
| held, first time | `Late` once, sent with the late header | the late digest |
| held after `Late` | stays held | as unknown |
| `expired` | lines re-offered into the next batch | the next digest |
| cancelled by forget | forgotten snapshots only removed | nothing (the owner asked) |
| queue unavailable (`ErrRecovery`, `ErrFull`, open or collect error) | collection retried at the next digest time; no batch is sent | the fixed outage line once that day (DC-8, provisional, SG-3) and a STATUS line while it lasts (OP-9) |

## W5-Db: sender contract (tier A)

**Requirements:** OP-1, OP-2; local clauses DB-1 to DB-7.

**Scope:** `broker/digestqueue/` (new `sender.go`; `queue.go`, `collector.go`, tests, `ASSUMPTIONS.md`), `docs/learning/digest-delivery-contract.md`, `broker/modemlink/` (`modemlink.go`, tests), `tools/risk_tier.py`, `tests/test_risk_tier.py`. Nothing in `cmd`, `owner` or `change`.

- **DB-1 (r3):** `digestqueue` is in `TIER_A_BROKER`; a test in `tests/test_risk_tier.py` asserts `broker/digestqueue/queue.go` is tier A.
- **DB-2 (gate):** `NewSender(q *Queue, t Transport, render func(Batch) (string, error), now func() time.Time)`. `Sender.Send(ctx, id)` calls `begin(id, now())`, renders that batch, calls `t.Deliver(ctx, text)` exactly once, and calls `finish` with the attempt `begin` returned. `Transport.Deliver` returns `(Outcome, evidence string)`. `Queue.Begin` and `Queue.Finish` become unexported in this package (W5-Da tests move to the internal names); no other exported function invokes a `Transport`, and a test asserts it by `go/ast` over the package's non-test files. A transport error, panic, cancelled context or missing receipt is `OutcomeUnknown`.
- **DB-3 (receipt):** `modemlink.Link.SendReceipt(to, text) (Receipt, error)`, with `Receipt` defined in modemlink. Leave `Send` and its callers unchanged. `Accepted` only on `bridgeproto.CodeOK`, with the item ID as evidence. `NotSent` only with proof the bridge never took the text: refused before queuing (unusable link, `MaxQueued`), or timed out while still in `l.queue` (checked under `mu`). Decided: of the bridge's codes only `CodeRecipient` proves not sent. `bridge.outbox` emits it without calling the modem for a non-owner line, and `codeOf` maps `at.ErrNumber` to it; `at.Modem.Send` never returns `ErrNumber` today (only `Dial` does), so for the owner line it is the line check. A test pins `CodeRecipient` to `NotSent`; if the builder cannot show from `bridge.go` that every `CodeRecipient` is emitted before the modem is called, it is `Unknown` too, recorded in `ASSUMPTIONS.md`. Handed then timed out, `CodeDown`, `CodeUnreachable` (it covers `EncodeSubmit` and mid-send errors alike), `CodeLimited`, `CodeRefused`, `CodeTooLong` and any unknown code are `Unknown`. modemlink must not import digestqueue; the adapter mapping `Receipt` to `Outcome` lives in W5-Dc.
- **DB-4 (r4):** `recover` finishes a held batch's acknowledgments; `Late` as in the decision above, once per batch, persisted, refused (`ErrState`) otherwise.
- **DB-5 (r2):** per-snapshot `Forget` as above.
- **DB-6 (expired, OP-1):** re-offer, `recover` skip and `Compact` as above; same parameters against a non-expired batch keep today's OP-1 behaviour.
- **DB-7 (doc):** the contract doc states the gate rule (structural, with the SG-3 exception), the four decisions and the source-side forget duty; its state machine gains `ready -> ready (Late)`; its clause table gains the new tests; the "Not guaranteed" line about W5-Db/W5-Dc points at this brief.

**Failing tests first** (names are suggestions; one per clause at least):
- `TestSenderRefusalNeverCallsTransport` (Expired, Unacknowledged, State, Recovery, Missing each leave the transport uncalled).
- `TestSenderTransportPanicOrCancelIsUnknown`, `TestSenderFinishFailureReopensUnknownNotResent`.
- `TestSenderRendersOnlyBegunBatch` (the render func sees the batch `begin` returned, `Sending`, attempt set).
- modemlink: `TestSendReceiptRefusedBeforeQueueIsNotSent`, `TestSendReceiptTimeoutBeforeHandIsNotSent`, `TestSendReceiptTimeoutAfterHandIsUnknown`, `TestSendReceiptOKCarriesID`; race detector.
- `TestRecoverFinishesHeldBatch`, `TestLateRearmsHeldOnce`, `TestLateRefusedOnFreshOrLateBatch`.
- `TestForgetRemovesOnlyMatchingSnapshots`, `TestForgetKeepsUnaffectedSourceCollectable` (a later `Collect` succeeds), `TestForgetLastSnapshotCancels`, `TestForgetInFlightRefusesBeforeMutation` (keep).
- `TestExpiredGenerationReofferedInNewBatch`, `TestRecoverSkipsExpired`, `TestCompactDropsSupersededExpired`, `TestSameParamsNonExpiredStillIdempotent` (OP-1: same hash returns the existing batch, different hash `ErrConflict`, for ready, sending, unknown and accepted).
- `TestOnlySenderSendCallsDeliver` (`go/ast`), `TestSendReceiptRecipientIsNotSent`, `TestSendReceiptOtherCodesAreUnknown`.
- Keep every W5-Da test green, changed only where a decision above replaces the behaviour it pinned (`TestCompactedExpiredBatchStillBlocksRatherThanWedgingSource` becomes the re-offer test; say so in the PR).

**Estimate/checkpoint:** 70k tokens; about 600 lines with tests.

## W5-Dc: wiring into agentosd (tier A)

**Requirements:** CH-15, OP-2, OP-9, CAP-3 (forget reach); local clauses DC-1 to DC-8.

**Scope:** `broker/cmd/agentosd/` (new `digest.go`, `digest_test.go`, `digestgate_test.go`; `main.go` for construction; `forget.go` for the hook only), `capoff.go` for new `capLines` registry entries only, `broker/digestqueue/ASSUMPTIONS.md` (wiring rows), `docs/owners-guide.md` (one paragraph on the digest). Not `capoff.go`'s `digestSources` (DIG-1's), not `change`, not `owner` beyond calling existing exported methods. OP9-status-b also edits `capoff.go`: whichever merges second merges main first.

- **DC-1 (open):** the queue opens at boot from a private file under the broker's state directory, through the existing `change.Store` file implementation, with explicit `Limits` constants in `digest.go`. Then `Collector.Recover` runs. Failure is the "queue unavailable" STATUS line, never a crash loop.
- **DC-2 (daily send, CH-15):** at the digest time (SG-2) each day: `Collect(created=now, expires=next digest time)`, then `Late` any held batch not yet late, then `Sender.Send` each ready batch, oldest first. `owner` has no quiet hours or unsolicited-text pacing today (only per-type caps for RESUME and challenge texts; `grants/gate.go`'s `Quiet` serves grants batching only), so W5-Dc ships none and invents none: the digest goes at the digest time, and quiet hours and pacing are release row W5-Dc-r1. Any check W5-Dc does apply runs before `Sender.Send`. The digest is never skipped for having nothing to say.
- **DC-3 (always sent):** a `day` source inside `digest.go` offers one generation per calendar day (generation = days since epoch, line "Nothing else today." (wording per r1) only when no other source is pending). Every daily batch is therefore non-empty and goes through the gate.
- **DC-4 (r1):** a `digest-status` source offers one line per surfaced batch (unknown, exhausted, held after `Late`) not yet carried in an accepted digest, with a persisted high-water mark so a line is carried once. STATUS gets one line per surfaced state while it lasts, and one for queue unavailable (OP-9). Each STATUS line is registered through `capLines.add` in `capoff.go`, so `ownerWorded` and the `capLineTexts` wording test check it; the digest's own lines live in one table in `digest.go`, checked by `ownerWorded` too.
- **DC-5 (transport):** the adapter maps `modemlink.Receipt` to `digestqueue.Outcome`; the text passes through `owner.Disclose` and `control.Fit` as `Inform` does.
- **DC-6 (gate test):** `digestgate_test.go` parses every non-test `.go` file under `broker/` (`go/ast`). `SendReceipt` is referenced only in `cmd/agentosd/digest.go`; the transport value built there is passed only to `digestqueue.NewSender`; the outage line (DC-8) is the one other digest-time owner text, sent from one named function that takes no batch.
- **DC-7 (forget, CAP-3):** `ownerForget` calls the queue's `Forget` (through the collector's lock) for the item's references before the forget counts as done. `ErrInFlight` keeps it owed on the existing retry path; it is never reported done.
- **DC-8 (queue unavailable, CH-15; provisional, SG-3):** when the queue is unavailable at the digest time, one fixed broker-worded line (no queued content, no source text) goes through `owner.Inform`, at most once per day, never retried, and the STATUS line stays. It is removed or kept as Mark rules on SG-3.

**Failing tests first:** a fake transport and fake clock drive a day: one accepted digest with the `day` line; an unknown outcome gives a STATUS line and one line in the next day's digest, and is never resent; a held batch goes out late once, then is surfaced; an expired batch's lines arrive next day; queue file unreadable gives the OP-9 STATUS line, one fixed outage line that day and no batch send; forget of an in-flight reference stays owed; the gate test fails if a second file under `broker/` calls `SendReceipt` or passes the transport elsewhere; a new STATUS line fails `capLineTexts` if misworded.

**Estimate/checkpoint:** 90k tokens; about 700 lines with tests.

## Order, model, review

W5-Db first, then W5-Dc. DIG-1 needs W5-Db only (the contract and `Source`); its sources go live through W5-Dc's collector. Whichever of DIG-1 and W5-Dc merges second merges main first and registers DIG-1's sources with the collector. Both packages are tier A by path (`modemlink`, `tools/risk_tier*`, `cmd`): strongest model, threat check in L3, Security 4a. The Sonnet pilot does not apply. Run `python3 tools/risk_tier.py --git origin/main HEAD` before each PR. One package per session.

**Threat check (L3/4a):** a second send path that skips `begin` (including the DC-8 outage line growing content); an unknown send resent; text rendered from anything but the begun batch; a forgotten reference sent after `Forget` returned; a `NotSent` classified without proof (any code but `CodeRecipient`, or a `CodeRecipient` emitted after the modem was called).

## Reuse (codex drafts, cut before #555)

Every `pkg/w5-d*-codex-*` branch carries its own pre-#555 `digestqueue` (no `Held`, `Late` or per-snapshot `Forget`), so nothing merges; lift by adapting to main's API. They stack: d62 contains d9 to d55.
- **DB-2:** `pkg/w5-d9-digest-attempt-codex-20261007`, `broker/digestqueue/bridgeattempt/attempt.go`: the Begin, render, one transport call, Finish flow. Drop its `Gate` seam and source allowlist. Lift its tests `TestExpiredOrUnacknowledgedDoesNotInvokeTransport`, `TestBeginSaveFailureDoesNotCallTransport`, `TestCancelledAndNilContextsDoNotBegin`, `TestAmbiguousTransportErrorsCannotRetry`, `TestAcceptedButFinishSaveFailureStaysQuarantined`, `TestCallbacksCannotMutateTransportPayloadOrPrivateQueueState`.
- **DB-3:** same branch, `broker/modemlink/modemlink.go`: the per-item `handed` channel read under `mu` and `SendCanceledError{Handed}` give the not-sent proof. Add what it lacks: separate refused-before-queue and timeout-before-hand from after-hand, and the item ID on `CodeOK`. Lift `TestOnlyAffirmativeBeforeHandoffCancellationPermitsRetry` and `TestWrappedOrMalformedCancellationDoesNotEstablishNonDelivery`.
- **DB-2/DC-2 test idea:** d11 `bridgeattempt/crash_test.go` (`TestAssembledDigestRecoveryAcrossEveryDurableBoundary`): cut at every durable boundary; a cut after `Begin` must end Unknown, never resent.
- **DC-2/DC-4 reference:** d32 `daily/workflow_test.go` (due-minute step, STOP mid-step), d33 `dailyhost/host.go` (`Run` single ticker with no catch-up backlog; `Status.Line()` without backend detail), d41 `dailypolicy/policy.go` (STOP and quiet check rechecked before the transport call). Patterns only: their registries and pacing stores are out of scope.
- **DC-3 test idea:** d30 `heartbeat/source_test.go` day-rollback and DST cases; its MAC'd state file is heavier than the `day` source needs.
- **Not reusable:** d4, d13, d24, d26 and `pkg/w5-sl-second-line-digest-draft` are source-side (DIG-1 or `owner` scope, older `Pipeline.Notice` path); d12 is owner-notice provenance; d55 and d62 are pacing-store recovery.
- **Write fresh:** `Late`, per-snapshot `Forget`, expired re-offer, `recover` skipping `Expired`, and the DC-6 `go/ast` gate test; no draft has them.

## Spec gaps (record in the PR; do not invent SPEC text)

- **SG-2:** SPEC lists "digest time" among the defaults (§ onboarding, line "The defaults (spend cap, … digest time …)") with no value and no owner setting exists in code. W5-Dc uses one constant, provisional 08:00 box-local time, until Mark sets it; the value and the owner setting are release row W5-Dc-r2.
- **SG-3:** CH-15 says the daily digest is always sent; OP-9 says an unavailable capability is reported, not hidden. SPEC does not say what goes out when the digest's own store is unavailable. Provisional default (DC-8): one fixed line that day, no queued content, plus the STATUS line. Mark rules on whether that line stays.

(An earlier draft's SG-1, digest wording, is not a spec gap: SPEC fixes the behaviour, and the words go through the UX lens and `ownerWorded`.)

Out of scope: the source adapters (DIG-1); D08 shared-ID collisions and UNDO expiry, D10 clock restriction (LATER W5-Da l1–l4 stay as they are); any SPEC.md change.
