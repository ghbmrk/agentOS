# W5-D6 nonconsuming question-book digest source

PeekDigest/AckDigest provide production source APIs over the book's actual
persisted digest lines and guard counters. No queue adapter, sender or daemon
integration is enabled. The existing Config.Path writer is reused; no second
store is introduced. A nonempty durable Path is mandatory for snapshot mode.

Peek returns one persisted immutable prefix, at most 64 lines/64 KiB. Summary
counters for secret-shaped refused answers and excess not-asked questions are
captured only when rendered in that snapshot. Later lines and counter increments
are untouched by acknowledgment of the earlier prefix. Snapshot mode excludes
legacy TakeDigest so mixed consumers cannot discard pending source state.
Existing callers remain in legacy mode until the first successful snapshot save.

A bounded persistent source state holds one pending snapshot, a monotonic
sequence/acknowledgment high-water and a private 32-byte receipt key. Domain-
separated HMAC receipts bind the exact prefix, rendered lines and captured counts;
old issued acknowledgments remain idempotent after restart/later generations
without an unbounded receipt ledger. The key never leaves private Book state.
Receipts are not owner answers, approvals, credentials or send authority and
must not become guest controls. Private directory ownership/encryption, backup,
retention and migration remain deployment requirements.

Pending snapshots and duplicate acknowledgments are re-saved before success so
a successful read alone is not taken as a durable commit. Source save failures
restore pending in-memory data and stop this digest source until reopen. Question
asking/answering keeps its existing behavior; source failure does not make an
untrusted question an approval or erase control-plane state. A caller must report
source/storage failure with fixed owner wording under OP-9 before integration.

The shared formatter preserves existing wording. A quoted question/default within
a broker template remains untrusted private data. Receipt integrity does not
sanitize that text or bypass CH-19: any future transport integration must apply
existing closed owner-output checks and preserve disclosure/provenance. This
package provides no exception to the digest queue's fixed broker-message boundary.
A reviewed question adapter must settle that source classification before sending.

The API does not establish owner visibility, carrier delivery, default correctness
or acceptance. It does not provide task/goal erase reach; queued source copies,
question text, backups and transport containment require coordinated forget and
retention integration. Older software can ignore these new Book state fields,
so rollback without a reviewed migration can reset source delivery ownership:
do not enable snapshot mode until that recovery contract is qualified.

Tests cover separately reopened real state files, nonconsumption, immutable
pending copies, prefix/counter increments, old idempotent receipts, tampering,
missing durable path, failed Peek/Ack writes, legacy-mode exclusion and bounded
prefix drainage. A counter-only snapshot must preserve a later first line; its
regression caught a nil/empty-prefix mismatch. No accounts/models/texts are used.
