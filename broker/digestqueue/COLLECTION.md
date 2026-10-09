# W5-D3 collection and partial-ack recovery

Implementation candidate stacked on W5-D2. This coordinator realizes the
admission/acknowledgment ordering in W5-D1; it does not provide production source
adapters or send texts. The source callbacks are trusted broker dependencies,
never agent callbacks. External security review precedes daemon integration.

`NewCollector(queue, sources)` freezes a map of source IDs to components, orders
it deterministically, and refuses invalid IDs, empty maps and oversized source
sets. Configuration is bounded by the queue's explicit source policy and the
16-snapshot batch limit. The source interfaces are not worker-visible tools.

Each Source supplies:

- `Peek(ctx)`: a nonconsuming immutable Snapshot or nil. It returns the same
  pending generation/hash until acknowledged, retaining new events separately.
- `Ack(ctx, snapshot)`: a durable, idempotent acknowledgment of that exact
  generation/hash. It rejects foreign/tampered snapshots, preserves later
  generations, and remembers acknowledgment across restart. A callback error may
  have committed its state; repeated identical Ack must therefore be safe.

A source uses `NewSnapshot` to bind its broker-owned source ID, generation, fixed
lines and forget-reference IDs. The snapshot is not an authority token. The
production adapter must enforce the contract against its real persisted state;
the synthetic source fixtures are not interchangeable with owner/change APIs.

`Collect(ctx, created, expires)` performs these steps while holding only its own
coordinator lock:

1. Recover every incomplete source acknowledgment from existing durable batches.
   Do not re-peek sources or regenerate existing snapshot timestamps/text.
2. Peek all configured sources; any failure leaves them unconsumed. Source-ID and
   snapshot consistency must pass before admission.
3. Persist one combined batch with Queue.Enqueue. Failed admission never calls
   a source Ack. Queue storage uncertainty requires reopening the Queue.
4. Ack each source, then persist that source's queue acknowledgment bit. A failure
   leaves the durable batch available for idempotent recovery; it never justifies
   creating another notification with a fresh ID.
5. Return the acknowledged ready batch. This is not transport acceptance or
   owner visibility, and no outcome/learning code is called.

A crash between source Ack and bitmap Save is handled by replaying that exact
source/generation/hash. The source may already consider the generation consumed;
its idempotence ledger answers the repeated Ack. If a newer generation now waits,
recovery of the older one must preserve it. New collection follows recovery so
an already queued snapshot cannot receive new times and become another batch.

A missing source blocks recovery. An expired batch with incomplete acknowledgments
also blocks, preserving pending source state; a ready batch past expiry with a
consumed source is reported by `Queue.Held` and is never expired or compacted. The caller must render a fixed
owner-facing status for unavailable/expired/storage-full states under OP-9 and
provide an explicit repair/migration path, not discard the association or declare
the source consumed. Raw returned errors are diagnostics, not owner wording.

Context cancellation is checked before reads, admission and callbacks and after
source acknowledgment; callbacks must honor deadlines. Cancellation after source
Ack can still leave a partial bitmap, recovered identically on the next call.
Callbacks run outside Queue.mu, but the coordinator lock serializes this instance.
Do not construct competing coordinators or file writers for the same queue.

Source invalidation, forget and actual transport dispatch need a reviewed shared
containment protocol. This coordinator's mutex does not create atomicity across
processes or against unrelated direct calls to Queue.Forget. Likewise, sender
priority, pacing, quiet hours, clock restrictions, authority/disclosure/resource
checks and transport evidence classification remain integration responsibilities.
Existing destructive Digest/TakeDigestNotes methods are not safe Source adapters.

Tests cover admission-before-ack, failure-before-admission, partial acknowledgment,
source-identity mismatch, unavailable source, expired hold, cancellation,
concurrent calls, newer generation preservation, and separately persisted queue
and synthetic source state reopened after a source-ack/bitmap-save interruption.
They do not establish actual carrier delivery, live source adapter behavior,
image storage/backup semantics, CAP-3 forget completion or a full acceptance gate.
