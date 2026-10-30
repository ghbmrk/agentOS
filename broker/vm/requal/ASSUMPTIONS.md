# Requalification runner: assumptions

Built for UPD-5r-b1 (#4032, brief `briefs/UPD-5r-b.md`) on slice a's `update.Runner` (#4031).

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| UPD-5r-b1-1 | **Cases and graders are the installed release's.** The candidate supplies neither: the runner takes a suite's cases from a host `Source`, sends only each case's input to the sandbox, and grades the output with a host `Grader`. The runner computes the suite digest itself, over every case's ID, input and expected answer, length-prefixed. | HLD-3 (the rules are not candidates), HLD-2 | `Run`, `digestOf`. |
| UPD-5r-b1-2 | **A suite with no source fails closed.** Missing cases or grader is `ErrNoSource`, which `Requalify` returns as an error, so the release holds. A source that exists and holds no cases scores 0 of 0 and boots nothing, which slice a's rule passes (a fresh box). So wiring the runner (b6) before the suite sources (b3 to b5) cannot lift the ship gate on empty suites. | UPD-5, ship gate (#3961 comment 6520945951) | `Run`. |
| UPD-5r-b1-3 | **Failure is asymmetric.** A candidate that errs or times out on a case fails that case. Any error in a baseline run, and a sandbox start or close error in either run, makes the run an error, because a broken baseline would lower the bar the candidate must meet. | HLD-3 | `cases`. |
| UPD-5r-b1-4 | **The evaluation budget is wall time per run, set by the installed release.** A spent budget is an error, never a partial score. Metering model calls against a separate budget (HLD-2) is the production sandbox's job (b2); a candidate that stalls every case until the budget runs out holds itself. | HLD-2 | b2. |
| UPD-5r-b1-5 | **One session per run.** All of a suite's cases run in one boot of the release; isolation between cases, if needed, is the sandbox's job. | — | b2. |
