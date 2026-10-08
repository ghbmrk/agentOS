# RES-t: P2-5r carry-forward (#124): checkpoint cut short

Board section: Backlog refill (2026-10-05).

P2-5r carry-forward from the #124 review: a checkpoint cut short by the lock-free preemption publishes no snapshot, even when the runtime reports success (Security R2, before REV-4 rollback is wired); no host or accelerator device reaches a machine (Security C1); an evaluation that loses its accelerator continues on the CPU (Potency); the floor test checks that a mid-checkpoint failure publishes nothing. Not here: pinning a pending owner rollback's snapshot against pressure pruning (Security R1, waits for owner rollback) and `cpu.weight` (budget R12)

**Needs:** P2-5r merged

**Gate:** skip (tests), security check

**State on the board before the 2026-10-08 index split:** merged (#129)
