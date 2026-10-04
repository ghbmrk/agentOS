# Agent-machine lifecycle: assumptions

Built for PLAN P1-4 against SPEC v0.12 (PR #15) on the broker skeleton
(PR #19). Each row is a reading of the spec, or a gap left for a later
package, that a reviewer may want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| V1 | A machine is a read-only image plus a host overlayfs upper layer, served to gVisor with gVisor's own overlay off (`--overlay2=none`). gVisor's internal overlay keeps writes in an opaque file, so the broker could not snapshot files without a full checkpoint. | REV-1, ARC-5, S3 | Firecracker (if it wins on the N95) needs a block-device layer instead; only `vm/gvisor` and `vm/overlay` change. |
| V2 | Per-step snapshot = pause, copy the upper layer (reflink where the file system has it), resume. Full checkpoint = the same plus `runsc checkpoint` while paused, so files and memory match. | REV-1 | Small: `Manager.capture`. |
| V3 | "Step" is whatever calls `Manager.Step`. The guest plane (P1-7) calls it after each broker tool call, on the machine that made it; a failed Step is logged and does not fail the tool call (G4). | REV-1 | — |
| V4 | Rollback is allowed to the machine's own snapshots and to the snapshot it was forked from, nothing else, so a machine cannot load another machine's data. | REV-4, REV-5 | `inLineage`. |
| V5 | `fork(n)` is all or nothing: every fork is admitted on its own full budget (forks share no memory, S3) before the source is checkpointed. Forks keep the source's class. | REV-4, CAP-1, RES-2 | `Manager.Fork`. |
| V6 | `merge` is a three-way file merge of a fork back into the machine it came from, against the fork point. Any path both sides changed differently is a conflict and nothing merges. The merged machine restarts on the merged files (a file-system rollback), so its memory is not kept. Keep-the-winner (CAP-1) needs no merge: keep the fork, destroy the rest. | REV-4 | A live in-guest merge would need guest cooperation (P1-7). |
| V7 | Data labels (REV-5) are tracked here because snapshots carry data: a label only rises; rollback, rebuild and merge never lower it; forks inherit it; reading a diff raises the reader to the snapshots' label. Egress enforcement is not here. | REV-5 | REV-5 package. |
| V8 | Preemption (RES-1) pauses the guest, keeps its files as a snapshot, kills it, and returns once its cgroup is empty, which is what `admission.Preempter` requires (memory released). In-memory state since the last full checkpoint is lost; the experiment resumes from its files. Checkpointing memory first would cost 2–4.5 s for an OpenClaw-sized guest (S3), too slow for a call. The frozen target time is not set yet. | RES-1, LOOP-1 | Checkpoint-then-kill as an option once the target is frozen. |
| V9 | A preemption that lands between a machine's admission and its start withdraws the admission; the machine does not start (`ErrRevoked`). | RES-1 | — |
| V10 | Every machine runs in its own cgroup v2 group: `memory.max` is the declared budget, `memory.high` is 1/16 below it (throttle before the stall S3 measured), swap is 0. The manager refuses to open without a cgroup parent unless told it is a test. | RES-2 | `cgroup.Child`. The 1/16 margin is unmeasured. |
| V11 | PSI comes from the machine parent group's `memory.pressure` (else `/proc/pressure/memory`). If PSI worked and then fails, it reads as +Inf, so only foreground is admitted. A host with no PSI at start-up admits on the budget alone. `-max-pressure` defaults to 10 % (unmeasured; size on the N95). | RES-2 | Flag. |
| V12 | ARC-2: the control-path packages still cannot start processes. `agentosd` (the composition root) opens the machine plane and hands it to admission as a `Preempter`. Only `vm/gvisor` starts a process, and only the configured runsc (`TestOnlyRunscIsExecuted`). | ARC-2 | `daemon/arc2_test.go`. |
| V13 | Broker restart: machines come back `stopped` with layers and snapshots intact; leftover sandboxes are killed. `Resume` restarts from the newest snapshot. | ARC-4 | — |
| V14 | Destroy keeps a machine's snapshots. Pruning by policy (RES-4) is not here. | RES-4 | Storage package. |
| V15 | Each machine gets its own broker services directory, `Config.Services`, mounted read-only at `/run/agentos` with gVisor's `--host-uds=open`; the sandbox has no other network. The directory is opened before every start or restore and closed on destroy. A fork gets its own directory; a connection it inherits from its source reads EOF after restore and never speaks for the source (integration tests). | ARC-6, REV-5 | — |
