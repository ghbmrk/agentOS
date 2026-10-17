# FUZZ-broker: native fuzz targets on the broker's state-transition code

Board row: issue #1813. Class: release. Tier: A (test files only, but in tier-A packages; `risk_tier.py` prints A). Usage estimate: 120k tokens, checkpoint at 90k.

**Why.** The tier-A packages below hold state across many calls (a gateway cache, live sessions, approvals, key slots), and their tests drive hand-picked sequences. A fuzzer that drives random sequences of the same operations against a small model finds orderings no table test names. Go's stdlib fuzzing needs no new dependency; the seeds run under plain `go test`, and a short `-fuzz` run in CI explores past them.

## Requirement (from SPEC.md)

- **DEV-2**: no component reaches the home network; the router's learned addresses are refused.
- **CH-7**, **CH-18**: the local page acts only within a live sign-in, and wrong codes are rate-limited.
- **CH-10**, **ADP-9**: an action that needs approval runs only on an approval of that same item, once, while fresh.
- **CRED-8**: the vault opens only with an enrolled factor.

Package IDs:
- **FUZZ-1** (netguard `Sources.Read`) Over any sequence of router moves before or after the router's answer, a returned external address is one that the gateway it was read on gave; the cache holds at most `maxGatewayExternals`; a nil error has prefixes.
- **FUZZ-2** (netguard gateway to policy) Over any sequence of moves, quick reads and refreshes, the policy's learned gateway's own external address is denied.
- **FUZZ-3** (netguard `Policy.Check`) For any network, pins, destination, port, protocol, purpose and name, an allow is sound: DNS only to the resolver on 53 over tcp or udp, a pin only for its purpose, anything else only to an address outside every special range, prefix and learned router address, with no hold. `OnDeny` runs at most once a call, never on an allow.
- **FUZZ-4** (localsrv sessions) Over any sequence of sign-ins (right or wrong code), sign-outs, owner locks and clock moves, at most `MaxSessions` tokens are live; a signed-out, expired, locked-out or evicted token is never accepted again; the wrong-code budget is never exceeded.
- **FUZZ-5** (grants approvals) Over any sequence of effects, flushes, approvals, denials, record changes, clock moves, stops, resumes and revokes, each intent runs at most once, only after an approval and no denial of it, to the recipient the approval named, within `DefaultFresh` of it, and never after its grant is revoked.
- **FUZZ-6** (vault slots) Over any sequence of host-slot adds and removals, passphrase rekeys with the right or wrong passphrase, and reopenings, the vault opens with a factor exactly when the model says it is enrolled, its canary reads back, and a refused rekey changes nothing.

**Acceptance tests:**
- FUZZ-1: `FuzzSourcesRead` (`broker/netguard/fuzz_test.go`, `REQ: DEV-2`).
- FUZZ-2: `FuzzGatewayPolicy` (same file).
- FUZZ-3: `FuzzCheck` (same file).
- FUZZ-4: `FuzzSessions` (`broker/localsrv/fuzz_test.go`, `REQ: CH-7, CH-18`).
- FUZZ-5: `FuzzApprovals` (`broker/grants/fuzz_test.go`, `REQ: CH-10, ADP-9`).
- FUZZ-6: `FuzzSlots` (`broker/vault/fuzz_test.go`, `REQ: CRED-8`).

## Design (recommendation)

Each target decodes its `[]byte` input as a list of operations over a small pool (three routers, a few intents, three hosts), applies them to the real package through the existing test fakes, and checks the invariant against a model after each step, in the style of `broker/hint/fuzz_test.go`. Netguard checks use a cancelled context so a held destination is denied at once. The oracles match on `errors.Is(err, ErrDenied)` only, not on hold wording or on `OnDeny` for a hold a cancelled context ended, which #2070 changes.

## Scope

PR A: `broker/netguard/fuzz_test.go`, `broker/localsrv/fuzz_test.go`, `broker/grants/fuzz_test.go`, `broker/vault/fuzz_test.go`, `briefs/FUZZ-broker.md`.

PR B (separate, Mark-only path under D-125): add the six targets to the fuzz loop in `.github/workflows/ci.yml`.

## Out of scope

Package code (a defect a target finds becomes its own finding and PR). `broker/netguard/policy.go` and `netguard_test.go` (#2070), `broker/grants/gate.go` and `grants/ASSUMPTIONS.md` (#2127), `image/fuzz-targets.json`. No `ASSUMPTIONS.md` change: the targets rest only on the package APIs already recorded.

## Done

CI green; FUZZ-1 to -6 covered by passing fuzz targets (seed corpus under `go test`, and at least 20s of `-fuzz` each locally with no failure).
