# S8-W1-tunnel-c-fu8: /seed with no plan login is a one-line 409

Board row: issue #1858. Source: PR #1850 delta reviews (Security 6196526329; Potency/UX/L3 6196542425). Class: release. Tier: A (`broker/cmd`). Builder: strongest model. Usage estimate: 40k tokens, checkpoint at 30k.

**Why (facts, verified at main edcd59c).** `broker/cmd/agentos-egress/workerroute.go`: `/seed` answers any seed error but a locked vault with a 500 carrying `err.Error()`. `PlanLogins.Seed` returns `egress.ErrNoLogin` when the owner has not signed in to the plan. `modelroute.RouteControl` (`broker/modelroute/workerroutes.go` `callQ`) maps a body that is exactly `no plan login stored` to `modelroute.ErrNoPlanLogin`, so a wrapped refusal (`codex: no plan login stored`) reads as a fault, and the status says fault either way. #1314 needs the refusal to read as "sign in first".

## Requirement (from SPEC.md and egress ASSUMPTIONS)

- **CRED-5** (SPEC.md:272) with egress assumption K28: each plan worker is seeded and served its own route; a missing plan login is the owner's to fix, not a fault.

Package IDs:
- **SEED-NOLOGIN-1** A `/seed` whose seed fails with `egress.ErrNoLogin`, wrapped or not, answers 409 with the one line `no plan login stored`. Any other seed failure stays a 500; a locked vault stays the one-line 503.
- **SEED-NOLOGIN-2** Over the control socket, `modelroute.RouteControl.Seed` returns an error that is `modelroute.ErrNoPlanLogin`, and neither `ErrVaultLocked` nor a fallback (`FallsBack`).

**Acceptance tests:**
- SEED-NOLOGIN-1: `TestCRED5SeedWithNoLoginIsOneLine409` (`broker/cmd/agentos-egress/seednologin_test.go`).
- SEED-NOLOGIN-2: `TestCRED5SeedWithNoLoginIsErrNoPlanLogin` (same file).

## Design

`errors.Is(err, egress.ErrNoLogin)` in the `/seed` case, after the locked-vault check, writes the sentinel's own text (not `err.Error()`) with 409. `RouteControl` already maps that body on any non-200, non-503 status, so `broker/modelroute` needs no change.

## Assumptions (recorded here: the egress ASSUMPTIONS.md is changed by open PRs)

- `PlanLogins.Seed` reports a missing login only as an error that `errors.Is` matches to `egress.ErrNoLogin` (`broker/egress/codexlogin.go` `load`).
- `modelroute.isNoLogin` matches the body text whatever the status; a change that ties it to 500 breaks SEED-NOLOGIN-2, which the test would catch.

## Scope

`broker/cmd/agentos-egress/workerroute.go`, `broker/cmd/agentos-egress/seednologin_test.go`, `briefs/S8-W1-tunnel-c-fu8.md`.

## Out of scope

`/open` and `/signin` with no login (they run `loginStore`, not the plan login). The CAP-11-plan note in #1858 (a seed leaves placeholder state until a create or `/close`): that is CAP-11-plan's. The `noLoginText` comment in `broker/modelroute/plan.go` still says "its 500": a later wording fix.

## Done

CI green; SEED-NOLOGIN-1 and -2 covered by the acceptance tests, which carry `REQ: CRED-5`.
