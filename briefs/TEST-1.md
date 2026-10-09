# TEST-1: Test hygiene (two LATER.md rows)

Started at the coordinator's request on 2026-10-09, a deviation from D-048 (LATER rows wait for the first release). The owner confirms the exception before this merges.

## Scope
Test files only: `broker/change/env_test.go`, `broker/change/split_test.go`, `broker/owner/review_test.go`. Also LATER.md (remove the two finished rows). No non-test change was needed.

## Requirements
- **TEST-1-1** (row "broker/owner review_test.go IDs"): `TestRestartHandsOpenRequestsToReissue` seeds its restart record with IDs the request-ID generator cannot issue. The generator (`newIDLocked`) builds `<letter><digit 2..9>`, so `Z1`, `Y1`, `X1` are outside its range.
- **TEST-1-2** (row "CH-21a f1"): `TestForgetGoalRewritesALaterAdoptionsUndo` no longer fails intermittently, with no skip.

## Root cause (TEST-1-2)
Not timing. `newEnv` leaves `Config.Rand` nil, so each env draws a random 32-byte split key. A case's dev/held-out side is `HMAC(key, id)`, 30% dev. A 12-case suite then has fewer than `MinHeldOut` (3) held-out cases about once in 4,500 envs (measured: 44 of 200,000 random keys). The candidate's evidence is then not `enough`, adoption needs the owner, and the test's owner says no: "setup: candidates rejected". Load only changes how often the suite is run, not the odds per run. Reproduced deterministically with a failing key (held=2).

## Fix
`newEnv` pins the split key (`pinnedSplitKey`, via `Config.Rand`); a test may still override it through `mod`. The same fix covers every test that builds a small suite through `newEnv`.

## Acceptance checks
1. `go test -count=1 ./change ./owner` (in `broker/`) passes.
2. `go test -race -count=50 -cpu 1,4 -run 'TestForgetGoal|TestEnvSplit' ./change` passes.
3. `TestEnvSplitKeyIsPinned` (REQ TEST-1-2) fails if the key is random or leaves fewer than 6 of the 12 standard cases held out.
4. `grep -n 'Z9\|Y9\|X9' broker/owner/review_test.go` prints nothing.
5. LATER.md no longer holds the two rows; TRACE.md is not in the diff.
