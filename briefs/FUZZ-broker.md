# FUZZ-broker: native Go fuzz targets on the broker's state-transition code

Board row: issue #1813 (Mark approved it 2026-10-15 12:07Z). Class: release. Tier: A (`risk_tier.py` prints A for test files in `broker/netguard`, `broker/vault`, `broker/grants`, `broker/localsrv`; the row's "tier B" was a guess). Builder: strongest model, in two sessions (see Split). Usage estimate: 90k tokens per package-session, checkpoint at 70k.

**Why (verified at main).** Fuzz targets exist mostly for decoders and parsers (about 20 packages, among them `sockets`, `hint`, `browser`, `update`, `loops`, `modemlink`, `guest`, `localui` `FuzzScanPassphrase`); ci.yml fuzzes five of them for 20s each through `tools/fuzzrun.py`. The state machines behind the tier-A invariants have none (netguard, vault, grants and localsrv have no target). Failure path it catches: an unexpected state transition that review missed, such as the unknown-to-known gateway MAC change and the failed revocation in #1725.

## Requirements

- **FUZZ-1** A `testing.F` target drives `netguard.Sources.Read` (`broker/netguard/sources.go:111`) and the gateway cache (`policy.go`) through random sequences of network readings and router answers, and asserts the invariants in `broker/netguard/ASSUMPTIONS.md`: an answer kept only for the gateway asked (same address, interface and MAC), a MAC that goes unknown to known drops the answer, and a second move returns `ErrGatewayMoved`.
- **FUZZ-2** A target drives the session table and sign-out in `broker/localsrv/localsrv.go` (`signOut`, `drop`, `valid`; localui's `signout` only forwards `OpSignOut`) through random open, use, expire and sign-out sequences and asserts that a signed-out or expired session never authorizes a request and that sign-out of one token leaves the owner's other live tokens valid (main's `signOut` drops only the presented token; revoking every session would be a SPEC question, not this brief).
- **FUZZ-3** A target drives grants and approval consumption (`broker/grants/grant.go`, and `gate.go`: `closeExpired`, `Narrow`; localui's approvals only forward) and asserts that an approval is consumed at most once, that a revoked grant never admits, and that an expired approval never consumes.
- **FUZZ-4** A target drives vault slots (`broker/vault/keyslot.go`, `keysbind.go`, `reencrypt.go`) through random add, remove, rotate and reopen sequences and asserts that the data key never reaches disk, that every committed slot opens the vault, and that a removed slot never does.
- **FUZZ-5** Each target is built on a model of the state (a small map or counter the target keeps beside the real one), so a divergence fails, not just a panic. Each target has seed inputs that run under plain `go test`, and a planted-defect control (the repository's pattern in `broker/sockets/fuzz_test.go`) showing it can fail.
- **FUZZ-6** The four new targets join the short fuzz step in `.github/workflows/ci.yml` (the `for t in sockets:FuzzRequest ...` list, run by `tools/fuzzrun.py`). The step runs each target at `--budget 20s` with no step budget of its own, so the four targets add about 80s to the fuzz step, inside the job's 30-minute timeout (ci.yml `timeout-minutes: 30`).

**Acceptance tests** (each carries `REQ:` for its ID; names are the recommendation):
- FUZZ-1: `FuzzGatewayIdentity` in `broker/netguard/fuzz_test.go`, and `TestFuzzGatewayIdentityCatchesMACMoveMutant`.
- FUZZ-2: `FuzzSessionSignOut` in `broker/localsrv/fuzz_test.go`.
- FUZZ-3: `FuzzApprovalConsumption` in `broker/grants/fuzz_test.go`.
- FUZZ-4: `FuzzKeySlots` in `broker/vault/fuzz_test.go`.
- FUZZ-5: each file's seed run passes under `go test ./netguard ./localsrv ./grants ./vault`, and each has one planted-defect control test that fails when the defect is switched on.
- FUZZ-6: `python3 tools/fuzzrun.py --pkg ./netguard --target FuzzGatewayIdentity --budget 20s` (and the other three) pass locally; the CI step lists them.

## Design (recommendation)

Stdlib `testing.F` only (no new dependency). Decode the fuzz bytes into an operation list with a small fixed grammar (op byte plus argument bytes), run it against the real type with injected clocks and fakes already used by the package tests, and compare to the target's model after each op. Reuse each package's existing test fakes; add none to non-test files. Keep every target under 50 ms per input so `fuzzrun.py` chunks stay large.

## Split

Session 1: FUZZ-1, FUZZ-4 (netguard, vault). Session 2: FUZZ-2, FUZZ-3 (localsrv, grants). FUZZ-6 is the `.github/` edit, which is a Mark-only file (CLAUDE.md, `premerge.py --needs-mark`): the builder proposes the one-line list change in the PR body and the PR is merged only on Mark's own approval at its head. Session 1 may leave FUZZ-6 to session 2 so there is one such PR.

## Assumptions

Builds after the G1 freeze lifts (D-118); it does not touch G1 code. The targets replace no existing one: the fuzz step grows by about 80s (four targets at 20s), inside the job's 30-minute timeout.

## Out of scope

Decoder fuzz targets (already covered), hardware-in-the-loop G1-e2e, long soak runs (`soak.yml`), any production-code change a target's finding calls for (file it as a release finding with the failing input stored under `testdata/fuzz`).

## Scope

`broker/netguard/fuzz_test.go`, `broker/vault/fuzz_test.go`, `broker/localsrv/fuzz_test.go`, `broker/grants/fuzz_test.go`, `.github/workflows/ci.yml` (FUZZ-6, Mark approval), `briefs/FUZZ-broker.md`. Stored corpus under each package's `testdata/fuzz/`.

## Done

CI green; FUZZ-1 to FUZZ-6 covered by passing tests; the PR names the builder model in its Budget section.
