# CODEX-sandbox-root: Root-cause the pid-namespace worker stall and add the outlives skip flag

Board section: Codex provider worker. Source: #1627 (release finding from #1612's reviews). Tier: C by `tools/risk_tier.py` (the issue's `tier:A` label assumed a change to `guest/codex/agentos-toolsh`; the finding below leaves the wrapper unchanged). Builder: strongest model. Usage estimate: 120k tokens.

**Why.** `test_descriptors_closed_in_a_pid_namespace_with_the_hosts_proc` timed out once at 60s on PR #1527 (head 0280567, 2026-10-14). #1612 gave the worker its own deadline and a stall report and stopped the beat tool inheriting the worker's pipes, but did not name a root cause. Review A4 asked for a way to skip the outlives probe (`tests/codex_worker/stub_cli.py`'s last phase), which waits out its 10s for a beat that a refusing wrapper never starts.

## Requirements

- **CODEX-sandbox-root-1** The stall is either fixed at its root or shown not to be the wrapper's, with the evidence in `tests/codex_worker/ASSUMPTIONS.md`. No retry, and no loosened or skipped test. The pid-namespace test passes 30 of 30 under CI-like load, and the `$$` mutant applied to the shipped wrapper still fails it.
- **CODEX-sandbox-root-2** (A4) `stub_cli.py --skip-outlives` skips only the outlives probe: the descriptor probe still runs, the beat tool never starts, and the result carries no `outlives` key. `assert_contained` fails such a result, so no containment test can pass with the probe skipped. Any other flag exits 2 without running a partial check. The pid-namespace test uses the flag for its `$$` mutant run only.

**Acceptance tests:** CODEX-sandbox-root-1 `tests/test_codex_worker.py::ToolSandboxTest::test_descriptors_closed_in_a_pid_namespace_with_the_hosts_proc`; CODEX-sandbox-root-2 `tests/test_codex_worker.py::ToolSandboxTest::test_skipping_the_outlives_probe_keeps_the_descriptor_probe_and_fails_containment`.

## Acceptance

Both tests (REQ-marked CRED-5, A14) pass; the load runs and mutant check are reported in the PR; CI green.

## Scope

`tests/test_codex_worker.py`, `tests/codex_worker/stub_cli.py`, `tests/codex_worker/ASSUMPTIONS.md` (new), `briefs/CODEX-sandbox-root.md`. **Guard files:** none.
