# S3: Agent machines at 8 GB

## Question
At the floor profile (HW-4: 4 modest cores, 8 GB RAM, no accelerator), which isolation technology should agent machines use: microVMs (Firecracker / Cloud Hypervisor) or containers plus a strong sandbox (gVisor, bubblewrap)?

Answered with measurements of:
1. per-instance memory overhead;
2. `checkpoint`, `rollback` and `fork(n)` times (REV-1, REV-4);
3. how many agent machines run concurrently in 8 GB.

Yes/no form: **do microVMs fit as the floor's agent machines?**

## Kill/pivot rule (PLAN.md §3)
If microVMs don't fit, use a lighter sandbox at the floor and microVMs above it.

"Fit" is judged against the floor memory budget proposed in RESULT.md, and against REV-1's "snapshotted automatically at each step", which needs a checkpoint cheap enough to run per step.

## Method
- Cloud container first (this spike), then the N95. The floor is simulated with a cgroup v1 memory limit of 8 GiB that every machine is launched inside, so anonymous memory, shmem, page cache and kernel memory are all charged.
- Same base rootfs (Ubuntu 24.04 base + Node 22) for every backend; each machine gets a private writable overlay over it.
- Workloads: `sh` (idle shell, isolates sandbox overhead), `node` (idle Node.js, the runtime OpenClaw uses), `agent` (Node with an incompressible heap and files on disk, for snapshot timings).
- Harness: `bench.py`; analysis helpers in `analysis.py` are unit-tested in `tests/test_s3_analysis.py`. Raw results: `results.jsonl`.

## Time box
About 3% of one week's plan allowance as a soft target (Mark, 2026-10-04: caps flexible). Stop and report once extra spend stops improving the answer.

## Out of scope
OpenClaw itself (S4), host OS choice (S7), credentialed browsers (S5).
