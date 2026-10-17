# S8-W1-tunnel-c-fu9: a refused refresh seen on a failed run still stops the route

Board row: issue #1891. Source: PR #1886 reviews (security 6203616648, 6204314613; potency/UX 6203715324, 6204226473). Class: release. Tier: A (`broker/provagent`). Builder: strongest model. Usage estimate: 40k tokens, checkpoint at 30k.

**Why (verified at main).** The issue lists six items. Only items 2 (S3) and the wording half of item 3 can be built now; the rest wait on inputs that do not exist at main (see Out of scope). In `Runner.Run`, `after(d, start)` runs only on the path where the CLI exited normally (`broker/provagent/run.go:321`). On the timeout, Exec-error and result-read-error paths the run returns `TimedOut` or `Failed` first, so a refused refresh that egress recorded during that run never reaches `signIn(d.ID, true)` and the route is not stopped. Failure path: a run times out after the provider refused the login's refresh; the next run is admitted and retries the dead login, against CRED-5 ("no retry", since retries can worsen a restriction), with no agentosd restart needed.

## Requirements

- **CRED-5** (SPEC.md:272) a refused login stops the route for every later run, with no retry.
- **FU9-1** On the timeout, Exec-error and result-read-error paths, `Run` still checks for a refused login recorded since the run's start and, if there is one, stops the route and sets the sign-in line (`signIn(d.ID, true)`). The run's own outcome stays `TimedOut` or `Failed` with no output; only the route state changes.
- **FU9-2** A run that fails for a reason with no refused login leaves the route running (no false stop), and a `Usage` error on that check is logged and does not change the outcome.
- **FU9-3** Provagent `ASSUMPTIONS.md` P5 and egress `ASSUMPTIONS.md` W7 are reworded to say what the credit rule covers today (a draw between two calls of one route, seen only with a reached-limit type or a pool at 100%), not "no run draws credits unmetered".

**Acceptance tests** (`broker/provagent/run_test.go`; each carries `REQ: CRED-5`):
- FU9-1: `TestTimedOutRunAfterRefusedRefreshStopsTheRoute`, `TestExecErrorAfterRefusedRefreshStopsTheRoute`, `TestResultReadErrorAfterRefusedRefreshStopsTheRoute`, each followed by a second `Run` that is `login-refused` without starting a worker.
- FU9-2: `TestFailedRunWithoutRefusalDoesNotStopTheRoute`, `TestUsageErrorOnFailedRunKeepsOutcome`.
- FU9-3: reviewed in the PR diff (text only).

**Revert mutant:** drop the new check on one failed path; the matching test must turn red.

## Design (recommendation)

Factor the refused-login half of `after` into `refusedSince(d, start) bool`; call it from the deferred cleanup that already runs on every post-start exit, guarded so the normal path (which calls `after`) does not call it twice. The check runs under no lock; `signIn` takes `r.mu` as today.

## Assumptions

Egress keeps recording `LoginRefused` for a run's route after the run's context ends (its `/usage` is read from the vault process, not the worker).

## Out of scope (stay on #1891, which the PR does not close)

- Item 1 (admission refuses a known `LoginRefused`): needs CRED-5b's persisted signed-in state, absent from `Usage` at main.
- Items 3 (the baseline code), 4 and 5: gated on #809 S8-live measuring the headers.
- Item 6 (reserve setting): lands after 4 and 5 so a nonzero reserve never ships without the no-spend read.

The builder edits #1891's body to tick items 2 and the wording half of 3 and leaves it open.

## Scope

`broker/provagent/run.go`, `broker/provagent/run_test.go`, `broker/provagent/ASSUMPTIONS.md`, `broker/egress/ASSUMPTIONS.md`, `briefs/S8-W1-tunnel-c-fu9.md`.

## Done

CI green; FU9-1 and FU9-2 covered by passing tests, FU9-3 in the diff.
