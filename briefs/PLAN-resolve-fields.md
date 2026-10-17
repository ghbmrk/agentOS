# PLAN-resolve-fields: field-aware plan-login resolve; measured header and refresh-field lists

Board row: work item #1756 (release findings from the #1014 build, ASSUMPTIONS W2, W4). Tier A (`broker/egress/worker.go`, the vault's `PlanLoginStore`). Needs: #1014 (merged), #809 S8-live captures for part B.

**Requirements:** CRED-5 (injection only at declared positions), CRED-1 (no token-bearing field reaches the worker unswapped), A14.

**Two parts, separable.**
- **A (buildable now): field-aware Resolve.** `PlanLoginStore.Resolve(provider, worker, placeholder)` becomes `Resolve(provider, worker, field, placeholder)`. The vault records which field each placeholder was issued for (`access_token`, `refresh_token`, `id_token`) and refuses a mismatch. `worker.go`'s two call sites (bearer at the Authorization position: `access_token`; refresh body: `refresh_token`) pass their field. Failure path: a route that resolves in a second position injects the refresh token where the access token belongs.
- **B (needs #809): measured lists.** `Codex().RequestHeaders` and the token response field set are replaced by what the S8-live capture shows, and the ASSUMPTIONS entries W2/W4 are marked measured with the capture reference. Until #809 has captures, B is not buildable; record it as blocked on the issue.

**Acceptance tests** (`broker/egress/resolvefield_test.go`, new; vault tests next to the store): CRED-5: `TestResolveRefusesPlaceholderOfAnotherField` (a refresh placeholder presented at the Authorization position is refused and the request fails closed; fails if the field argument is ignored); `TestResolveAcceptsPlaceholderAtItsOwnField`; `TestRefreshBodyResolvesOnlyRefreshPlaceholder`. CRED-1: `TestUnknownRefreshResponseFieldRefusesAllOrNone` (retained). B, when built: `TestRequestHeadersMatchCapture` against a synthetic canary capture file.

**Revert mutants.** Ignore the field in the store; let the bearer position pass `refresh_token`; leave a captured-but-unlisted response field out of the swap.

**Threats Security must check.** A placeholder issued for one field resolving in another; placeholders from another worker or provider; the interface change leaving a caller on the old signature (compile error, not silent).

**Scope:** `broker/egress/worker.go`, `broker/egress/codexlogin.go` (`PlanLogins.Resolve`), `broker/egress/worker_test.go` (`fakeLogins`), `broker/cmd/agentos-egress/workerroute_test.go` (`planLogins`), `broker/egress/resolvefield_test.go` (new), `broker/egress/ASSUMPTIONS.md`, `briefs/PLAN-resolve-fields.md`. **Guard files:** `broker/egress/` is tier A through the core list (`broker/core/core.txt`); `workerroute.go` only passes the `PlanLoginStore` type and needs no change, but `workerroute_test.go` does, so the #1857 wait still holds.

**Conflict (D-111) at 2026-10-17 00:14Z.** #2015 holds `broker/egress/{exchange,proxy}.go`; #1857 holds `workerroute.go`; #1783 holds `broker/egress/codexlogin.go`. Part A starts after those merge.

**Usage estimate:** 60k tokens for A. Builder model: strongest (tier A); two reviews.
