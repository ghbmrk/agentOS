# UPD-5r-b: the requalification runner, split

Work item #4032 (slice b of `briefs/UPD-5r.md`; slice a is #4031, PR #4033). Written 2026-10-30 against main at 656af2cd plus #4033 at 472a5a34. Slice a's brief gave an outline and said this brief splits it if the suite sources are missing. They are, so this file splits it into b1 to b6 and specifies b1, the row #4032 now carries.

## What main shows

- **No sandbox boots a release.** `broker/vm` runs agent machines (an image plus an overlay under gVisor); nothing mounts a candidate's `/usr` image. The old change engine never booted one either: `ProposeRelease` scored the image digests as tree files through an `Evaluator` that `broker/replay` (deleted) implemented.
- **No suite sources.** The kernel log (`broker/kernel/state.go`, `task.go`) has tasks, plans, steps and step results (`step.result`: outcome and detail only), but no owner outcome record per goal (KRN-9), no recorded clerk response bodies to replay (HLD-2), and no security cases held as log data (HLD-5). `broker/kernel/sim` is a test fixture, not a replay gate. `broker/corpus` holds four closed-check payloads, not a suite.
- **No consumer.** UPD-7w (#3961), the release check that calls `Requalify`, is queued, so nothing in `cmd/agentosd` would call a runner today.

## The split

Every row is tier A. A suite with no source is an error from the runner, which `Requalify` treats as fail closed, so wiring (b6) can land before b3 to b5 without lifting the ship gate on empty suites. The gate lifts only when all three sources exist and the security suite holds at least one case: slice a's rule passes an empty held-out or replay suite (a fresh box's real state) but fails an empty security suite, so b3 ships at least one case.

| Row | What | Scope | After |
|---|---|---|---|
| **b1** (#4032) | The host-side runner: cases from the installed release, a sandbox session per suite run, scoring by host graders, fail closed | `broker/vm/requal/` | #4033 |
| b2 (#4044) | The production sandbox: the release's `/usr` image, checked against its `UsrRootHash`, run read-only under gVisor with no network and one case socket; plus the in-image case driver it talks to | `broker/vm/`, `image/` | b1 |
| b3 (#4045) | Security suite as log data: §16's injection tests and HLD-5's minimized regression cases, append-only, removable only by an owner key; its grader | kernel log type (D-159 row first), `broker/vm/requal/` | b1 |
| b4 (#4046) | Held-out suite: one outcome record per goal (KRN-9) and the dev/held-out split (HLD-3); its grader | kernel log type (D-159 row first), `broker/vm/requal/` | b1 |
| b5 (#4047) | Replay suite: recorded clerk responses in the log, and the host check that counts steps the recorded keys would not admit (HLD-2) | kernel and clerk (D-159 row first), `broker/vm/requal/` | b1, b4 |
| b6 (#4048) | Wiring: `update.NewRequalifier` with the runner, passed to UPD-7w's check in `cmd/agentosd` | `broker/cmd/agentosd/` | b2, UPD-7w (#3961) |

b2 to b6 are their own `work-item` issues; each one's builder writes its full brief section here.

## b1: the host-side runner

`broker/vm/requal/requal.go`, package `requal`. `*Runner` implements `update.Runner`.

- `Case{ID string; Input, Expect []byte}`: a case held by the installed release. Only `Input` reaches the sandbox; `ID` and `Expect` stay on the host.
- `Source` (`Cases(ctx) ([]Case, error)`) and `Grader` (`func(Case, []byte) Grade`, with `Grade{Pass bool; Unadmitted int}`) per suite, in `Config.Suites` keyed by `update.SuiteHeldOut`, `SuiteReplay` and `SuiteSecurity`. Both are installed-release code: the candidate never supplies a case or a grade (HLD-3, "the rules are not candidates").
- `Sandbox` (`Start(ctx, rel *update.Verified) (Session, error)`, nil `rel` is the installed release) and `Session` (`Run(ctx, input) ([]byte, error)`, `Close() error`). b2 builds the production one.
- `Config{Sandbox, Suites, CaseTimeout, Budget}`; `New(Config) (*Runner, error)` refuses a nil sandbox and non-positive limits.

**Rules of `Run(ctx, rel, suite)`:**
1. A suite with no entry, source or grader is `ErrNoSource` (fail closed: the gate holds). A source that errs is an error, never an empty suite. A non-nil `rel` that is not checked (`!rel.OK()`) is refused.
2. The runner computes `Digest` itself over the cases (ID, input, expect, length-prefixed), so a source cannot name one suite and serve another. Duplicate case IDs are an error.
3. An empty suite boots nothing and scores 0 of 0; slice a then fails it only for security.
4. One session per run; every case gets `CaseTimeout`, the whole run `Budget` (HLD-2's evaluation budget, set by the installed release). Running out of `Budget` is an error, never a partial score.
5. **Asymmetric failure.** A candidate whose session errs or times out on a case fails that case. A baseline (`rel == nil`) whose start, case or close errs makes the run an error, since a broken baseline would lower the bar the candidate must meet. A start or close error is an error for both.
6. `Unadmitted` sums the graders' counts on the replay suite only.

**Requirement IDs:** UPD-5, HLD-2, HLD-3.

**Acceptance tests** (`broker/vm/requal/requal_test.go`, marker `REQ: UPD-5, HLD-2, HLD-3`): `TestHostGradesWhatTheSandboxReturns`, `TestOnlyTheInputReachesTheSandbox`, `TestSuiteWithoutSourceFailsClosed` (also through `update.Requalifier`: the verdict is an error, never passed), `TestEmptySuiteBootsNothing` (also through `update.Requalifier`: all suites empty fails on security), `TestSourceErrorIsAnError`, `TestDigestNamesTheCases`, `TestDuplicateCaseIDsRefused`, `TestCandidateErrorFailsTheCase`, `TestBaselineErrorIsAnError`, `TestBudgetSpentIsAnError`, `TestUnadmittedCountsOnReplayOnly`, `TestNegativeUnadmittedCountsAsNone`, `TestUncheckedReleaseRefused`, `TestRequalifyThroughTheRunner` (slice a's rule end to end: a regressing candidate fails, an equal one passes).

**Scope:** `broker/vm/requal/requal.go`, `requal_test.go`, `ASSUMPTIONS.md`; `briefs/UPD-5r-b.md`. No new import outside the module; `broker/vm/` is open under the G2 freeze; not trusted core.

## Estimate

b1: about 150 lines of code and 300 of tests, 60k to 90k tokens. b2 and b5 are the large rows.
