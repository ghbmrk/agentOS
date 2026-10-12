# WS-rest: Nothing private at rest on a workstation: no private text in swap, caches or dumps

**Owner:** primary lane (unclaimed).
**Priority:** release. **Class:** release. **Implementation risk:** tier A.
**Board section:** Controller and helper system (D-102).
**Requirements:** HW-11
**Acceptance:** A1.
**Dependencies:** WS-image

## Finding

From PR #1054 (D-102): its Findings line and the L3 and combined-lens reviews at e87a918 and 6afe260; source design spec/controller-helper-system.md §10. A workstation receives private content yet HW-11 says helpers hold nothing private at rest. PR #1054 specified no mechanism for swap, caches or dumps.

## Scope and intended change

`image/` workstation profile (swap off or encrypted with a per-boot key, tmpfs for caches, core dumps off), a raw-disk canary test in `tools/hostcheck.py`, tests, ASSUMPTIONS.md.

Keep all private content in memory: no persistent swap (or swap under a key that is gone at power-off), model and work caches on tmpfs, no crash dumps, no logs of content. Canary text in a private task must not appear on any block device.

Do not edit SPEC.md; a needed spec change goes on the PR's Findings line.

## Acceptance tests

1. Run a private task with a synthetic canary, power off, and find no canary on the raw disk, swap or logs.
2. The same canary run with swap pressure forced finds none.
3. Invariant C: no credential reaches the workstation.

Failure path: A stolen workstation yields private text from swap.

Synthetic canaries and addresses only. Mark tests with `REQ:` comments.

## Handoff and estimate

Initial checkpoint: 80k tokens, an estimate rather than a ceiling. If it will not finish under 150k, split by acceptance test and say so on BOARD.md.
