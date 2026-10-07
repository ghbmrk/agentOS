# W5-D5 production pipeline-to-queue adapter

`changesource.New(pipeline)` implements the collector Source interface for the
real change pipeline. Configure it under `changesource.ID` (`change`). It calls
PeekDigest, never the destructive Digest method. No daemon, sender, provider,
owner-outcome or implicit-acceptance path is enabled by importing the adapter.

The queue snapshot carries a bounded broker-private Receipt containing the exact
pipeline snapshot needed to replay source Ack after restart. Its generation,
lines and references must match the queue payload; the queue content hash binds
the receipt too. The adapter strictly decodes the receipt, refuses extra JSON or
unknown fields, cross-checks queue/source contents, then lets the pipeline verify
its scoped issuance receipt and acknowledge the exact events durably.

This extends queue snapshots with an optional `receipt` field; absent receipts
retain their existing hash encoding. Existing queue state can be loaded, while
older software's strict decoder refuses files containing the new field. Rollback
and migration still need review. The 128 KiB receipt ceiling is a representation
bound, not a frozen product quota; serialized queue capacity remains explicit.

Receipts contain broker-private event/version metadata and goal references, not
provider credentials or the pipeline's private signing key. They are not owner
codes, approvals or send authority. Do not forward receipts or whole Batch JSON
to transport: only reviewed fixed owner-facing Lines are eligible for rendering.
Private queue/source storage, encryption, retention, backup and recovery remain
integration requirements. Snapshot hashes alone are not authentication.

The collector admits the complete receipt/payload durably before source Ack. If
a source Ack commits but the queue bitmap does not, reopening both actual source
and queue files recovers that same Ack through the retained receipt without a new
source generation or notification ID. Later source notices stay pending. Older
issued receipts remain idempotent after later acknowledgments.

Validate checks receipt binding, issuance and pending-snapshot invalidation only.
It cannot prove a queued goal/reference is still valid, that UNDO/MORE remains
live, or that a sender is allowed to dispatch. The pipeline's pending-only forget
invalidation does not cover already acknowledged queue copies. Before an owner
forget completes, integration must serialize source/queue invalidation with send,
purge all affected payloads, reconcile unresolved delivery and cover backups.
No end-to-end CAP-3 or transport acceptance gate is claimed.

Tests use the real change Pipeline, queue and Collector, with a synthetic evaluator
that refuses any attempted model evaluation. They cover actual separately reopened
files after partial acknowledgment, newer-notice preservation, old idempotent
receipts, changed/rehashed queue content, tampered source metadata, malformed/
foreign receipts and cancellation. No account, guest or external text is used.
