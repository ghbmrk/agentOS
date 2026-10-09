# W5-D1: durable digest notification contract (design before implementation)

W5-D1 — source snapshots and digest delivery, frozen design questions

Correction to the initial proposal

modemlink.Link currently has an in-memory queue/out map and no persistent store.
Its outage behavior deliberately drops missed texts and reports a fixed recovery
summary; it does not replay those missed messages. Reusing its wire protocol does
not make a digest durable. A durable digest outbox must be a separate narrow
notification class with a reviewed persistence boundary. Do not automatically
replay approval codes, stale decisions or third-party effects through it.

change.Pipeline.Digest consumes Listed/RevertSeen/notice state, while owner.Channel
TakeDigestNotes clears counters/notes. Those sources need nonconsuming snapshots
and explicit acknowledgment, or an equivalent transactional integration. A
save-after-read reorder is insufficient. The current owner auto-reply on-time
semantics already use owner Queued.Late and grants/loops provenance. Digest queue
admission must not replace or fabricate that visibility evidence, and this package
must not weaken the existing implicit-acceptance caps or explicit-anchor rules.

Proposed records (broker-owned, private state)

SourceSnapshot {source_id, generation, watermark, snapshot_hash, fixed_lines,
                referenced_ids, created_at}. Repeated peeks return the same
pending generation; new notices get a later generation. Acknowledgment of G must
never erase events appended after G. Rendering is deterministic broker wording.

DigestBatch {batch_id, source_snapshots, rendered_hash, destination_reference,
             created_at, expiry, policy_version, state, attempt_ids,
             bridge_item_ids, last_receipt, visibility_status}.

State: ready -> queued-durable -> sending -> transport-accepted | delivery-unknown
| retryable | expired. Source consumption occurs only after queued-durable.
A source ack retry is idempotent for source+generation+snapshot_hash. A duplicate
batch insertion with different rendering/source digest is rejected, like OP-1.
Do not confuse transport acceptance, carrier delivery and actual owner visibility.

Persistence sequence

1. Read snapshots without mutation, select paced lines and validate shared IDs.
2. Persist batch and exact source associations with atomic replace/fsync under
   existing state-storage conventions; storage failure leaves sources pending.
3. Ack only included source generations. Crash here retries idempotently using
   persisted associations. Sources never clear newer notes during an older ack.
4. Attempt send through existing priority/quiet-hours policy and bridge protocol.
5. Persist observed transport outcome. If acknowledgment is lost, mark delivery
   unknown and follow a bounded, reviewed retry policy. A fresh notification ID
   cannot prove the old text was not delivered. No exactly-once SMS promise.
6. Preserve unresolved/expired notice state for fixed STATUS/digest recovery
   wording. Do not imply an owner saw a line merely because it was queued.

Batch ID should be derived from a persistent scheduler sequence plus source
snapshot associations (not text alone, since identical notices can recur).
Separately deduplicate by associations. Compaction retains enough ack/dedupe
state to prevent resurrecting already-consumed source generations. Encryption,
retention/forget and recovery inventories include the new private state.

Concurrency and capacity

One broker-owned collection/send coordinator, with source generation locks and a
bounded persistent queue. No blocking send under the pipeline/channel source
lock. STOP/STATUS and approvals keep their current priority. Full queue preserves
pending sources and emits a fixed failure status; it never silently drops a new
notice. A tick that runs after restart or clock restriction must not shift the
release of a disclosure hint to an agent-chosen time. IDs stay in the shared
allocator while their referenced commands remain live; expiry wording matches
actual UNDO/MORE validity. Pending forgotten-source snapshots must be removed or
re-rendered before send; do not leak erased task text in a queued digest.

Proposed crash-test oracles

D01 kill before batch persist -> source unchanged; no batch.
D02 partial write/save/fsync error -> source unchanged; restart sees old valid state.
D03 kill after batch persist, before ack -> one batch; ack on replay, no second batch.
D04 new source event between peek and ack -> older consumed, newer stays pending.
D05 two concurrent collectors -> one association per source generation; no lost line.
D06 bridge outage/lost receipt -> unresolved delivery recorded; no implicit owner
    acceptance manufactured; retry bound and potential duplicate text documented.
D07 queue full/expiry -> source recovery visible; no stale approval/code replay.
D08 shared-ID collision/UNDO expiry -> commands bind only their current source item.
D09 forget before send -> affected private text is never sent after forget completes.
D10 clock restricted/quiet hours/approval backlog -> fixed pacing; control priority.
D11 crash during compaction -> valid queue+dedupe associations survive together.
D12 old persisted format -> migration is explicit, reversible before enabling sender.

Review decisions required

Storage boundary and fsync guarantees; per-source generation semantics; whether a
carrier receipt supports any visibility claim; retry/expiry/queue-size numeric
policy; shared-ID lifetime; migration/forget/recovery behavior. No runtime sender,
source mutation API or optimizer has been implemented. W5-D2 and W7-A remain
subsequent small packages with the earlier design's authority constraints.

A10 experiment readiness

The dependent H6 measurement harness in tools/measure_trials.py validates locally supplied
trial records and hashed evidence without launching a model or account action.
It keeps API dollars, tokens, runs and quota units separate, rejects incomplete
three-arm comparisons, and includes rejected trials in owner effort per accepted
task. Self-test fixtures do not measure product benefit. A10 product baselines
remain unavailable until an assembled image, unmodified OpenClaw/direct CLI,
qualified routes and owner-reviewed workload/goal judgments are supplied.
