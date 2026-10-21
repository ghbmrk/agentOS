# Kernel simulator: assumptions

Built for MIG-2 (#2525). `broker/kernel/sim` replaces the journal simulator (SIM-sim, 6cf8b16) and drives the kernel and the fake mail clerk from one seed. Each row is a reading a reviewer may want to change.

| ID | Assumption | Spec basis | If it changes |
|---|---|---|---|
| MIG-2-sim-a | **One seed fixes everything**: a PCG source drives the planner, every fault, the nonces and the clock. The same seed gives a byte-identical log. | KRN-6, EVL-1 | A map iteration in the kernel's write path would break it; `TestSameSeedGivesTheSameLog` catches that. |
| MIG-2-sim-b | **The disk is durable when `Append` returns**; a crash armed on the nth append leaves a random prefix of that frame. Open trims it. | LOG-2 | A file system that reorders appends needs a richer model. |
| MIG-2-sim-c | **Concurrency is modelled as nesting.** A revoke, STOP or pause lands inside the clerk's `Do` (`race`), between the kernel's check and the effect, and the clerk's own `Check` must refuse it. A double delivery models a retried call; the clerk dedupes by idempotency key. | CLK-2, KRN-8 | Real goroutine interleavings are covered by `-race` on the unit tests. |
| MIG-2-sim-d | **The world judges every effect on the spot** (stop, revoked key, unknown root, verb outside the key, hold window) and the sim checks after every operation that replay equals the live state and every effect has a dispatch entry in the log. | KRN-1, KRN-5, KRN-8 | none |
| MIG-2-sim-e | **The planner is hostile**: foreign-signed, tampered, unlogged-root and derived keys; planner-sourced arguments; reused plan ids; an oversize plan. | KEY-1, KEY-2 | none |
| MIG-2-sim-h | **The world is the real `clerk.Mail`** with seeded faults and the true clock, so the sim proves the clerk code that ships, not a copy; the world only judges each effect the clerk applies. The two mutants are the only clerk code of its own: one acts on the kernel's word, one forgets every key it ran. | EVL-1, CLK-2 | none |
| MIG-2-sim-i | **Reach over realism in the op mix.** The owner resumes whenever STOP is in force, stops only on a third of the draws, and half the derived keys carry a short hold (10 and 30 minutes), so plans are admitted and holds are reached at all: before this, 40 seeds gave 40 effects and one hold. | EVL-1 | Rebalance if a counter in `TestSweepFaultsTakeEffect` falls to zero. |
| MIG-2-sim-f | **Two mutants prove the sweep bites**: a clerk that trusts the kernel, and a clerk that does not dedupe. Each is found within 100 seeds. | EVL-1 | Add a mutant when a new invariant is added. |
| MIG-2-sim-g | **Seed budget**: 40 seeds of 200 operations by default (`SIM_SEEDS` widens it). Replaying after every operation is quadratic, so the sweep is bounded by that, not by the kernel. | EVL-1 | Raise it in a soak job. |
