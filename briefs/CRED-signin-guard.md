# CRED-signin-guard: a sign-in reopens a stopped route only when it stored a login

Board row: #1925 (state-machine audit 2026-10-16, R2c). Tier A (credentialed sessions).

## Failure paths (verified on main at 639eb9c)

- `provagent.Runner.SignedIn(provider)` clears the provider's route stop and sign-in line unconditionally. Its one caller (`awaitSignIn`) checks `SignInStored` first, but the method itself does not, so any future caller (a resume path, a page handler) reopens a route the provider refused the login on without a stored sign-in (CRED-5: no retry until the owner signs in again or resumes).
- `holder.Holder.Hand` replaces the secret with no check, and `holder.Keeper` hands whatever `Secret()` returns whenever the holder is empty. After the provider refuses the login (a declared refused-login status, `Operation.RefusesLogin`), a holder restart makes the keeper hand the same revoked login back, and egress's route stop is in memory only (#1926), so the box can retry a refused login.

## Fix

1. `Runner.SignedIn(provider, worker string) bool` asks `SignInStored(worker)` itself and leaves the stop and sign-in line in place (returns false) when there is no `SignInStored`, or it says no. `awaitSignIn` uses its answer.
Split (G1 freeze, coordinator 2026-10-16): fixes 2 and 3 are in `broker/holder/`, outside `tools/g1_scope.txt`. They moved to #2009 (CRED-holder-revoke), which waits on the freeze; this package delivers fix 1 only.

2. (#2009) The holder marks its login revoked when the provider answers a declared refused-login status with that login. While revoked it spends nothing (503 `revoked`), `GET /state` says `revoked`, and `Hand` of the same login is refused (`PUT /secret` 409); a different login replaces it and clears the mark.
3. (#2009) The keeper remembers a fingerprint of a login the holder reported revoked (or refused on hand) and never hands that login again, including to an empty holder after a restart. A different login from `Secret()` (the owner signed in again) is handed, also to a holder that is held but revoked.

Out of scope: persisting route stops across a broker restart (#1926, next row on the same files); `egress.Proxy.Resume`'s owner-code check (left to its caller, CH-10); `broker/provagent/declare.go` (owned by #1951).

**Requirements:** CRED-5

**Acceptance tests:**
- CRED-5: `broker/provagent/signin_test.go::TestSignedInNeedsAStoredSignIn` — `SignedIn` with no `SignInStored`, or one that says no, leaves a refused route stopped and the owner not told again; with a stored sign-in it reopens. Catches the unconditional clear.

**Scope:** `broker/provagent/run.go`, `broker/provagent/signin.go`, `broker/provagent/*_test.go`, `broker/provagent/ASSUMPTIONS.md`, `broker/cmd/agentosd/planwire_test.go` (one call site of the changed signature), this brief.

**Needs:** nothing. #1951 touches `broker/provagent/ASSUMPTIONS.md`; rebase that file's rows if it lands first.

**Usage estimate:** ~80k tokens.
