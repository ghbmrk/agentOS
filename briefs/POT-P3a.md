# POT-P3a: Qualify private replay capture and effect matching

**Owner:** primary, unclaimed. **Class:** release, A7/A10/A11. **Tier:** A.
**Requirements:** CHG-1/2, LOOP-5/6, CRED-1/7, CAP-3, OP-4/7, REV-5.
**Needs:** review the POT-P3 result contract; L1 agreement on capture/custody and independent CHG-2 approval. This is an activation dependency, not a request to weaken redaction.

## Blocking finding

The daemon's journal defaults redact free text before the grants owner-outcome callback receives its intent snapshot. P3 correctly withholds such snapshots: treating the common redaction marker as an exact effect would permit false matches. Under that default, its new mail.send grader has no usable production evidence. Keep P3 draft; do not activate or merge production wiring that enables it until this qualification passes. Synthetic unredacted fixtures prove only the result protocol.

## Design and implementation scope

Design a bounded broker-owned capture/matching path that distinguishes canonical effects before information is lost while preserving CRED-7, private-data custody and FORGET. Keyed matching is a design candidate, not an adopted cryptographic protocol. Keys and expected outcomes never enter a guest, builder, prompt, public hint, log or ordinary journal text. Do not expose raw fields merely to make replay pass. Reuse existing vault/journal/replay custody mechanisms and declare exact affected paths in the implementation brief after L1 review.

Bind captured evidence to the immutable original intent, account, goal, terminal outcome, canonicalization/version and source provenance. Keep permission, execution and authenticated quality separate. Define capture persistence, key lifetime/rotation, crash reconciliation, record retention, deletion and restore before coding. Recorded external responses needed by a task must be separately qualified; missing responses fail, never fabricated success.

## Acceptance before P3 activation

1. With unchanged production redaction enabled, a real daemon→journal→settlement→harvest→isolated replay fixture produces a usable accepted mail.send case. Changing account, recipient, subject or body fails its grade even when ordinary journal text is identical after redaction.
2. Wrong key/version, missing capture, unknown/failed settlement, stale/foreign task, duplicate effects and incomplete response recordings fail closed. Candidate-controlled output cannot supply a capture or select its key, contract or owner outcome.
3. Crash cuts neither mark incomplete capture usable nor lose the effect's identity. Key rotation and policy changes invalidate prior evaluation eligibility where necessary. FORGET/restore removes or invalidates the capture, suite case and derived candidates, without a cache resurrection.
4. Canary checks show neither private text nor matching keys reach unintended logs, public products, unrelated tasks or the guest's oracle view. Dev/held-out partitioning remains unchanged; no live external effects occur in replay.
5. Fresh strongest-model L3, separate Security review, Linux CI and independently approved CHG-2 activation pass. Only then may primary enable P3. A cross-compile or synthetic grading unit test does not satisfy this gate.

Initial checkpoint: 20k tokens for design and one capture slice; split custody, durable storage and qualification if needed. No runtime change is implemented by this brief.
