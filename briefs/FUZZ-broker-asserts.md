# FUZZ-broker-asserts: the broker fuzz targets assert what the FUZZ-broker brief names, and show they can fail

Board rows: issues #2238 and #2239, both release findings from the delta L3 review of #2149 (FUZZ-broker). Tier: A per the issues' labels and `briefs/FUZZ-broker.md`; the coordinator handed it to a tier-C builder because the diff is test files only, so `tools/risk_tier.py` on the real diff decides before the PR opens (OPERATING §3). Builder: Sonnet-class. Usage estimate: 60k tokens, checkpoint at 90k.

**Why (verified at main).** `broker/netguard/fuzz_test.go` never references `ErrGatewayMoved` (FUZZ-1 names it); `broker/vault/fuzz_test.go` never scans the files it writes for the data key (FUZZ-4 names it); only `broker/sockets/fuzz_test.go` has a planted-defect control, though FUZZ-5 asks for one per target. Failure path: a change makes a second gateway move return a cached answer or nil, or a rekey writes the unwrapped key into the keys file, or an oracle quietly stops checking; each target stays green.

## Requirements

- **FUZZ-1** `FuzzSourcesRead` and `FuzzGatewayPolicy` assert that `Sources.Read` and `Policy.Refresh` return `ErrGatewayMoved` exactly when the gateway moved during both router requests of one read, and a seed input drives that case.
- **FUZZ-4** `FuzzSlots` scans the vault file and the keys file after every operation for every data key the vault has held, raw, hex and base64, and fails when one appears.
- **FUZZ-5** Each of `FuzzSourcesRead`, `FuzzGatewayPolicy`, `FuzzCheck`, `FuzzSessions`, `FuzzApprovals` and `FuzzSlots` has a planted-defect control: its oracle is factored to report through a small interface, a recorder collects what a planted defect trips, and the same input passes against the real code (the pattern in `broker/sockets/fuzz_test.go`).

Doc comments: the targets' `FUZZ-n` numbers already match main's FUZZ-1..4 (checked); `FuzzCheck` stays the "extra" target, so there is nothing to renumber.

**Acceptance tests:**

- FUZZ-1: `TestFuzzSourcesReadReportsAPlantedDefect` (a swallowed second move), `TestFuzzGatewayPolicyReportsAPlantedDefect`, and the seed runs of `FuzzSourcesRead` / `FuzzGatewayPolicy`.
- FUZZ-4: `TestFuzzSlotsReportsAPlantedDefect` (a leaked key), and the seed runs of `FuzzSlots`.
- FUZZ-5: `TestFuzzSourcesReadReportsAPlantedDefect`, `TestFuzzGatewayPolicyReportsAPlantedDefect`, `TestFuzzCheckReportsAPlantedDefect`, `TestFuzzSessionsReportsAPlantedDefect`, `TestFuzzApprovalsReportsAPlantedDefect`, `TestFuzzSlotsReportsAPlantedDefect`.

## Design

Each target's body moves into a function taking a `fuzzT` (the `Helper`/`Fatalf` part of `testing.T`) and an optional planted defect; `FuzzX` calls it with the real `*testing.T` and no defect. The defects live in the tests and change nothing outside them. Test files only; no production code, no new dependency.

## Assumptions

Recorded in `broker/netguard/ASSUMPTIONS.md` terms: the fake host's router moves are the only way a gateway key changes; a `*testing.T` and a recorder behave the same to the oracles.

## Out of scope

Production-code changes, new targets, the `.github/` fuzz step (FUZZ-6, Mark-only).

## Scope

`broker/netguard/fuzz_test.go`, `broker/vault/fuzz_test.go`, `broker/localsrv/fuzz_test.go`, `broker/grants/fuzz_test.go`, `briefs/FUZZ-broker-asserts.md`.

## Done

CI green; FUZZ-1, FUZZ-4 and FUZZ-5 covered by the passing tests above; the PR names the builder model in its Budget section.
