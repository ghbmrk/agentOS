# SR2-4i: Host side of SR2-4

Board section: Backlog refill (2026-10-05).

Host side of SR2-4 (L3 and security on #155; budget R12, R14): the host image enables iocost (`io.cost.qos` `enable=1`) on the state disk so `io.weight` takes effect, a boot health item reports when it is off, and the unit file's `TasksMax` is left at its default or set explicitly; optionally write `io.bfq.weight` where BFQ is the scheduler. Measure STOP and the preemption target (R6) under a CPU-busy pool, and the 4096 and 1024 task figures, on the N95 run (A2). L3 carry: when the root's `pids.max` reads `max` but an ancestor slice is capped, the 1024-task reserve is not guaranteed; read the effective cap up the tree or set `TasksMax` on the unit so the root carries it

**Needs:** SR2-4 merged; host image

**Gate:** skip (host config), security check

**State on the board before the 2026-10-08 index split:** queued, blocked on the host image
