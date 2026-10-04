# S3 result: agent machines at 8 GB

Labels: **[Measured]** in this spike, **[Source]** from a primary source, **[Inference]**, **[Rec]**.

## Answer

**Do microVMs fit as the floor's agent machines? Not measured here, and memory will not decide it.**

1. **Nested virtualization is not available in the cloud container** (no `/dev/kvm`; the container is itself a Firecracker guest). Firecracker and Cloud Hypervisor could not be run. Their numbers below come from Firecracker's own specification, not from measurement.
2. **The guest, not the sandbox, sets concurrency.** Sandbox overhead is 1–16 MiB per machine [Measured]. One unmodified OpenClaw machine is about 1.6 GB (S4, PR #1). At the floor that allows **2 concurrent OpenClaw machines** under the proposed memory budget, whichever isolation technology is used [Inference from both].
3. **What does separate the options is snapshot semantics.** gVisor restores a full running machine (memory and files) in 0.2–0.55 s [Measured]. That makes `rollback` and `fork(n)` skip OpenClaw's 27 s cold start. bubblewrap can only snapshot files, so every rollback or fork restarts the guest.
4. **Pivot rule (PLAN.md §3) not triggered on the evidence so far.** [Rec] Ship **gVisor as the floor's agent machine** now: it is measured and needs no KVM. Re-run this harness with Firecracker on the N95, because its copy-on-write snapshot restore could make `fork(n)` cheaper than gVisor's (see "Still to measure").

## Environment

Cloud container: 4 vCPU Xeon @ 2.1 GHz, 16 GB RAM, no swap, kernel 6.18, cgroup v1. **The floor was simulated with an 8 GiB memory cgroup** around every machine, so anonymous memory, shmem, page cache and kernel memory all count. The disk is a virtio volume, not a USB SSD. The Xeon cores are faster than the N95's, so the times below are lower bounds for the floor.

Backends:
- **bubblewrap 0.9.0**: namespaces only, no network. The overlay is mounted on the host because 0.9 has no `--overlay`.
- **gVisor release-20260928.0** (`runsc`, systrap platform, no KVM, `--network=none`): user-space kernel; the root overlay is backed by a file on disk.

Both use the same Ubuntu 24.04 base rootfs plus Node 22, with a private writable layer per machine.

## Measurements

### Memory per machine (32 machines, least-squares slope) [Measured]

| Backend | Idle shell | Idle Node.js | Start to ready, Node (median / p90) |
|---|---|---|---|
| bubblewrap | 0.7 MiB | 8.3 MiB | 44 / 58 ms |
| gVisor | 15.9 MiB | 23.4 MiB | 146 / 213 ms |
| Firecracker | ≤5 MiB VMM [Source] + guest kernel and page cache (unmeasured) | — | ≤125 ms to guest init [Source] |

The Node row is the sandbox plus an idle Node runtime. **gVisor costs about 15 MiB more per machine than bubblewrap.** At a 1.6 GB guest that is under 1%.

### Filling 8 GiB with idle Node machines [Measured]

| Backend | Machines alive at the limit | What happened at the limit |
|---|---|---|
| bubblewrap | 972 | Reclaim stall: launches stopped making progress. **No OOM kill**; failcnt was about 3.8 M |
| gVisor | 345 | The same stall |

**Surprise:** at the cgroup limit with no swap, the kernel did not kill anything. It thrashed reclaiming page cache (including the Node binary's code pages), and machines stopped responding. This is exactly the "swap thrashing" RES-2 forbids, without any swap. So the broker has to refuse admission *before* the limit; the kernel will not save it.

### checkpoint / rollback / fork(n), median of 2–3 runs [Measured]

The workload is Node holding H MiB of random (incompressible) heap and D MiB written to its root filesystem. H=1600 stands in for one OpenClaw machine.

| Backend | H / D (MiB) | checkpoint | snapshot size | rollback | fork(n), total | Process state kept? |
|---|---|---|---|---|---|---|
| bubblewrap | 128 / 64 | 68 ms | 64 MiB | 0.28 s | n=4: 1.1 s | No (files only; guest restarts) |
| bubblewrap | 512 / 256 | 0.12 s | 256 MiB | 0.76 s | n=4: 10.8 s | No |
| bubblewrap | 1600 / 64 | 28 ms | 64 MiB | 1.5 s | n=2: 9.3 s | No |
| gVisor | 128 / 64 | 0.13 s | 229 MiB | 0.20 s | n=4: 0.86 s | **Yes** |
| gVisor | 512 / 256 | 0.38 s | 795 MiB | 0.36 s | n=4: 2.9 s | **Yes** |
| gVisor | 1600 / 64 | 1.9 s | 1.7 GiB | 0.55 s | n=2: 2.8 s | **Yes** |

Every rollback was verified: the restored machine was running and its file had the expected size.

- bubblewrap's rollback and fork times are mostly the guest restarting. For OpenClaw, add its 27 s cold start (S4) to every bubblewrap rollback and fork.
- bubblewrap's checkpoint time is a frozen `cp -a` of the writable layer, so it grows with files written. Reflinks on btrfs/XFS would make it near-constant; this ext4 volume has none.
- gVisor's checkpoint is a full image: about the guest's resident memory plus the files it wrote, written at roughly 0.9 GB/s here. **Forks share no memory**: two restored 1.6 GB machines cost 3.5 GB.

## What this means for the spec

1. **Per-step snapshots must be filesystem-only.** A full checkpoint of an OpenClaw machine is 1.7 GiB and about 2 s on this disk, and slower on USB. Doing that "at each step" (REV-1) would quickly exhaust RES-4's storage reserve. Files-only snapshots cost tens of ms. [Rec] Two tiers: a filesystem snapshot every step, and a full-state checkpoint at policy points (a warm template after the guest starts, before risky steps, and on demand for `fork`).
2. **Warm templates replace cold starts.** Checkpoint each guest once after start-up and restore from that image: 0.55 s instead of 27 s.
3. **At the floor, `fork(n)` has n ≤ 2 for OpenClaw** under gVisor (no sharing between forks). CAP-1 already allows N=1 at the floor, which is consistent with this.
4. **Admission must hold headroom** (RES-2), because the limit stalls instead of killing. [Rec] Use cgroup v2 `memory.high` below `memory.max` per machine, and admit only when the measured free pool covers the guest's declared size plus a margin.

### Proposed floor memory budget (8 GB) [Inference; to be checked on the N95]

| Component | Budget |
|---|---|
| Host image + broker + journal | 1.0 GB |
| Local inference (small model, speech, embeddings; CPU) | 2.0 GB |
| One credentialed browser | 0.5 GB |
| Admission headroom (no-stall margin) | 0.6 GB |
| **Agent-machine pool** | **~3.9 GB → 2 × OpenClaw (1.6 GB + sandbox overhead)** |

## Proposed SPEC.md diff (for L1 / spec v0.12; SPEC.md not edited)

```diff
- **REV-1** ... Every agent machine is snapshotted automatically at each step, and snapshots are broker-held, so the agent cannot delete them.
+ **REV-1** ... Every agent machine's filesystem is snapshotted automatically at each step. Full-state
+   checkpoints (memory and filesystem) are taken at policy points: after guest start (warm template),
+   before steps the broker classes as risky, and for `fork`. All snapshots are broker-held, so the agent
+   cannot delete them.

- **RES-2** A per-component memory budget is declared and enforced by cgroups. The broker refuses admission that would breach it. No swap thrashing, no out-of-memory kills of broker or foreground.
+ **RES-2** A per-component memory budget is declared and enforced by cgroups, with a soft limit
+   (`memory.high`) below the hard limit. The broker refuses admission that would leave less than the
+   declared headroom, because a cgroup at its hard limit stalls in reclaim rather than failing fast
+   [S3]. No swap or reclaim thrashing, no out-of-memory kills of broker or foreground.

  | **CAP-1** | Speculative parallelism | ... N is set by measured free RAM; at the floor N may be 1 (sequential).
+   At the floor with an OpenClaw-sized guest (~1.6 GB), expect N ≤ 2 [S3, S4]. |

+ Agent machines use a user-space-kernel sandbox (gVisor) at the floor. A microVM backend MAY replace
+   it where KVM is available and it measures better on the same harness (spikes/S3-agent-machines).
```

## Still to measure on real hardware (N95)

1. **Firecracker** (KVM is available on the N95: the N95 has VT-x): idle overhead with a minimal guest kernel; snapshot create/restore; and **memory shared between forks**. Firecracker maps the snapshot memory file `MAP_PRIVATE` [Source], so forks share unmodified pages copy-on-write. That is the one place microVMs could beat gVisor at the floor. Measure balloon/free-page reporting too, since guest memory is otherwise not returned to the host.
2. All the timings above on the N95's cores and on the USB 3.2 SSD, which sets checkpoint write speed.
3. The memory budget table, with the real local-inference model and a credentialed browser running.
4. gVisor's systrap overhead on a syscall-heavy guest (npm install, builds).
5. Reflink-capable filesystem (btrfs/XFS) for per-step snapshots; depends on the S7 host choice.

## Surprises

1. Memory limit reached → stall, not OOM (above).
2. `runsc` resolves container IDs by **prefix**: with machines `d1` and `d10`, `runsc kill d1` is refused as ambiguous, and the first run hung on that. The broker must use fixed-width or terminated IDs.
3. gVisor makes a `readonly` OCI root read-only even inside its overlay, so the root must be declared writable for the overlay to take writes. The base image stayed unmodified (checked).
4. bubblewrap 0.9 (Ubuntu 24.04) has no `--overlay`; the overlay has to be mounted by the host (the broker).

## Security note (input to L3, not a review)

bubblewrap alone is namespaces over the shared host kernel. That is a thin boundary for REV-1's "root, install packages, run code" guests. gVisor puts a user-space kernel between the guest and the host. A microVM puts a hardware boundary there. So bubblewrap alone is not a candidate for agent machines, even though it is cheapest.

## Model usage

About 0.17 M tokens processed by this thread, by the session's own counter. That can't be converted to a share of the weekly allowance from inside a session (PLAN.md §4A, B-6). [Inference] Probably within the ~3% soft target; Mark's next usage screenshot calibrates it. Most of the spend went to two harness bugs: the runsc ID clash and readiness waits that ignored their timeout.

## Reproduce

As root on Linux with cgroup v1 memory+freezer, `bwrap` and `runsc` on PATH, and the Ubuntu base rootfs plus `node` at `/srv/s3/base` (path set by `S3_WORK`):

```
python3 bench.py density --backend gvisor --workload node
python3 bench.py fill    --backend gvisor --workload node --cap 1200
python3 bench.py ops     --backend gvisor --heap-mb 1600 --disk-mb 64 --forks 2 --reps 2
```

Raw rows are in `results.jsonl`.
