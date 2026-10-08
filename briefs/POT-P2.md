# POT-P2: Bind durable tasks and track native draft revisions

**Owner:** primary, unclaimed. **Class:** release, A3/A10/A15. **Tier:** A.
**Requirements:** OP-4/7/8, ARC-7, CAP-3/5, REV-2/5, CH-3.
**Needs:** P3-7/W3-goal, W5 delivery/recovery contracts, SR3-5 for native mail identity. Coordinate existing W5 draft stack; do not rebuild its outbox.

## Design boundary and scope

`broker/guest/goal.go` conservatively declines attribution when two tasks are open and expires last-goal fallback after the quiet period. Preserve that behavior until a broker-authenticated execution context replaces it. Propose task lifecycle and guest protocol semantics through L1 before implementing them; this brief does not amend SPEC. Proposed paths: guest goal/delivery plumbing, daemon task hooks, existing durable owner state and focused tests. Split native artifact tracking into a second implementation slice with `broker/mail/` and adapter tests.

Bind calls, worker runs, effects, artifacts and results to a broker-owned execution context. Never accept a guest-selected goal or budget token as authority. A progress message must not complete work. If the guest cannot support overlapping bound contexts, admit one active task per context rather than guess.

Track only broker-created drafts by account/object/version. A native edit is untrusted task data, never an authenticated command or send approval. Material changes invalidate older approvals. Bound tracking and delete derived data under CAP-3.

## Acceptance

1. Two overlapping tasks, a long-running task, a worker descendant, restart and retry preserve the correct task and budget; replayed or guest-forged IDs cannot select another reservation.
2. Waiting, delivered, accepted, corrected and cancelled remain distinct. Delivery failure or a progress reply cannot mark completion. Cancellation/STOP keep their existing authority.
3. Phone edits to one tracked draft reach only its original task. Unrelated Drafts, account swaps, UIDVALIDITY changes and old versions cannot overwrite it or authorize an effect.
4. Correction, deletion and restore remove or invalidate dependent evidence; a held-out outcome is not exposed as guest input.

Tests first, Linux/race checks, fresh L3/threat check and separate Security/lens passes. Initial checkpoint: 20k tokens for the design and 25k per implementation slice. Existing conservative attribution remains until the new path qualifies.
