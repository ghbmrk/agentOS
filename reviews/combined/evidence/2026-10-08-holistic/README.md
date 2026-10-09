# Holistic architecture review: evidence scope

Reviewed source: `3c9f9e711be3d394537cb9e6aedc5b4ee394e2c0`, 2026-10-08. The [report](../../2026-10-08-holistic-architecture.md) distinguishes implemented properties, source inferences, known limitations and proposed stronger guarantees. Tests below used that source on native macOS arm64 with Go 1.26.8. No live account, real model, reusable secret or remote operation was used.

## Reproduce the synthetic probe

From any directory, with the repository's required Go version installed:

```sh
GO=/path/to/go sh reviews/combined/evidence/2026-10-08-holistic/run-probe.sh
```

Run that relative path from the repository root, or use its absolute path from elsewhere. The runner uses vendored code with network/toolchain downloads disabled. Its program and build cache live in a temporary directory removed on exit. It changes no runtime source or persistent recall store.

[Probe source](recall-hint-probe.go.txt) calls the actual recall API, inserts two synthetic private records in an in-memory index, and asserts both account IDs are returned and the caller is raised to private. [Captured output](probe-output.txt):

```text
owner-scope recall: label=private accounts=[synthetic-client-A synthetic-personal-B]
largest hint-kind value-space bits: 12.677720
```

This confirms the current owner-wide private search domain. It is **not** a confidentiality bypass, live cross-account disclosure, or test of a scoped task contract that does not yet exist. The probe supplies a synthetic labeler and no embedder; it does not qualify daemon wiring, persistence or isolation.

The second number is `hint.Default().MaxBits()`: the maximum log2 value-space size **within one hint kind** (the shipped `skill_gap` space). It does not include an arbitrary choice among kinds, count a full daily set, measure an observed leak, or prove guest control of hints. The report uses H9's separate documented estimate for the set of up to five hints per day. K1 requires broker-derived facts; the report preserves that requirement.

## Existing Go tests

From `broker/`, with a writable external Go cache and synthetic loopback servers allowed:

```sh
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off go test -mod=vendor -count=1 ./vault ./journal ./browser ./egress ./recall ./hint ./change ./reversible ./skill ./recalltool
```

All ten packages passed; see [captured package results](go-tests.txt). The author subreviews additionally inspected the relevant fixture constructions. Browser's real Playwright fixture skips because AI-mode snapshots are unavailable on this host. A package pass must not be read as that fixture passing. Earlier sandbox runs refused synthetic loopback listeners; the final command above was rerun with loopback permitted.

These checks support local package claims, not production Linux service identities, gVisor/cgroup isolation, browser credential sessions, floor-host throughput, TPM/boot or owner usability. No hardware, physical phone, actual account or measured accepted-task benefit was qualified.

## Required repository checks

`python3 tools/doclint.py`, `python3 tools/trace.py --check` and `git diff --check` passed. The required native Python suite ran 214 tests: **6 failures, 33 skips**, no errors. [Failure summary](python-check-summary.txt) records the six Linux canary/sweeper failures. Linux `/proc` sweeping is unavailable and product targets use Linux-only Go APIs on this Darwin host. This is an environment-limited result, not a green local suite; Linux PR CI is the authoritative execution for those checks. CI results are recorded in the PR, separate from this fixed-source local evidence.

## Import inventory and review limits

[Daemon import inventory](daemon-first-party-imports.txt) contains 51 unique first-party packages from the union of `go list -mod=vendor -deps ./cmd/agentosd ./cmd/agentos-egress` on the reviewed source. This is a coupling inventory, **not** the number of trusted components, executable processes, vulnerabilities, or a measure of the TCB's size. The two processes have different custody privileges.

Three author source reviews covered credential/effect authority, data/provenance lifecycle and execution/leverage. Fresh independent L3 and architectural challenge verdicts are linked in the PR. They evaluate this advisory report/intake; they do not establish the proposed runtime guarantees or certify the system secure.

## Simple text/call follow-up

The [separately pinned interface evidence](simple-interface-evidence.md) records source `a52a678a4f4d854eaf737ffaa8c3777781efea56`, focused owner/question/modem checks and native test limits. It does not extend the original probe into a voice or usability qualification.
