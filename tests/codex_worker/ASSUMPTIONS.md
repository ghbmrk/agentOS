# Assumptions: the Codex worker test harness

What `tests/test_codex_worker.py` and its stubs rest on, beyond `guest/codex/ASSUMPTIONS.md`.

| ID | Assumption | Serves | If wrong |
|----|------------|--------|----------|
| T1 | **The pid-namespace stall (#1527, #1542, #1616) was bwrap's /proc lookup, not the wrapper.** bwrap 0.9's launcher opens `/proc/<pid>/ns` for the child it clones, by the child's pid in the launcher's own namespace, and dies if that is missing; the child then blocks for good waiting on it. Under the host's /proc that pid number names a host process or nothing, so the run failed only on runners whose low pids had a gap at that number, and passed on re-run. Reproduced 2026-10-27: in a `--unshare-pid` worker with the host's /proc, a nested bwrap failed with `open /proc/9/ns/ns failed` exactly when host pid 9 was free. The pid-namespace worker (`ToolSandboxTest.worker(pidns=True)`) now brings an outer namespace whose sleepers hold every pid below `PIDNS_HELD` (128); the test passes with 12 held, fails with 3, and passed 30 of 30. | CRED-5, A14 | The pid-namespace tests fail if a run needs a pid at or above `PIDNS_HELD`, or if a bwrap update changes the lookup. |
| T2 | `stub_cli.py --skip-outlives` is used only on runs that assert descriptors, never containment: `assert_contained` requires `outlives` to be exactly False, so a skipped probe fails it. | CRED-5, A14 | A containment test using the flag fails, never passes. |
