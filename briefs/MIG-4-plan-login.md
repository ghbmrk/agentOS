# MIG-4-plan-login: the model clerk holds the plan login for its CLI guest

Work item #3104, prerequisite for #2780(b). Tier A. Split into three slices on the issue (comment 6397037553); this brief covers slice (a) and names (b) and (c) so their scope is fixed.

**What main has.** `broker/clerk/model` meters calls in front of an abstract `Provider`. Nothing on main holds a provider's consumer plan login for a CLI guest: no placeholder in the guest, no injection into its requests, no refresh swap (CLK-7). The only production path is the old core's (`egress/codexlogin.go`, `egress/exchange.go`, `egress/worker.go`, driven by `provagent`), which is frozen and will be deleted. Its behaviour was measured on Codex CLI 0.162.1 (#809) and reviewed over many rounds, so this row ports it rather than redesigning it. Nothing new imports the old code.

**Slice (a), MIG-4-plan-login-a: custody and exchanges** (`broker/clerk/plan`, a new package). It is not package `clerk`: the kernel's process links that package for its check (a KRN-2cap root), and this code parses a guest's requests and a provider's answers, so placing it there would grow the trusted core by about 1,300 lines. In its own package it is linked only by the model clerk's process. It seals its one value with `clerk.Sealer` in a `Store` of its own (CLK-1).
1. `PlanDeclaration`: the plan's endpoints (model, read, refresh, and the sign-in guest's device and code steps), each a method, path, host and query keys; the exact token answer (declared fields, kinds and text patterns); the account claim in the `id_token`; the refused-login error codes; the request and response header lists; the code exchange's redirect rewrite; a version. `Codex()` is the Codex declaration as measured.
2. `Login`: one plan login in its own sealed `Store`, bound to the plan's name. `Guest` gives a guest its placeholder token set; the placeholders are per guest and resolve for no other. `Do` serves one guest request. At a model or read endpoint the guest's access placeholder becomes the real token and the clerk opens the upstream connection itself, through the guarded transport. A refresh carries the guest's refresh placeholder in its body. It runs as one flight per login, and the answer is swapped back to each joining guest's own placeholders, committed to the store before release. A guest's refresh never sets or changes the account. Only a sign-in guest (`BeginSignIn`) reaches the device and code steps, and its code exchange may set the account. `SignedIn` is the only success signal.
3. **Drop and stop.** A token answer out of its declared shape, without an account, or naming another account on a refresh is dropped, never forwarded, and stops the route (`unswappable`). It stays stopped until a release changes the declaration's version (requalify). A refresh answered 400/401 with a declared refused-login code stops the route (`refused-login`) until `Resume` (the owner's `PLAN <plan> ON`, authenticated by its caller) or a new sign-in. Both are sealed with the login, so a restart keeps them. A stop the store cannot record is held in memory (fail closed).
4. **Redaction.** The injected token is redacted from response headers and from the streamed body, without holding back more than a partial match.

**Not in (a).** The responses endpoint's request-body schema and hosted-tool refusal, quota headers, metering, and the guest-facing listener are (b): `broker/clerk/model`, `broker/clerk/run`. The worker that runs the CLI's device-code sign-in, the owner-socket calls (begin, state, resume, remove), and the CLK-7 mode gate are (c): `broker/clerk/run`. `cmd/agentosd` is #2780(b).

**Requirement IDs:** CLK-1, CLK-3, CLK-4, CLK-7, PLN-5.

**Scope (a):** `broker/clerk/plan/` (new: `plan.go`, `store.go`, `plan_test.go`, `ASSUMPTIONS.md`), `tools/trusted_base_parsers.txt` (one `parser` line), this brief.

**Guard files:** `tools/trusted_base_parsers.txt` (the new package is a parser; the PR body carries a `Trusted-base:` line). `tools/risk_tier.py` already classes `broker/clerk/...` as tier A, and no core root links the package, so `tools/trusted_core.txt` is unchanged.

**Acceptance tests:** slice (a), all in `broker/clerk/plan/plan_test.go`:
- `TestPlanGuestHoldsOnlyPlaceholders` (CLK-1): after a sign-in, a guest's token set holds no real value, and its id_token carries the account. Fails if a real token reaches the guest.
- `TestPlanInjectsOnlyAtDeclaredEndpoints` (CLK-3, CLK-7): a model call with the guest's placeholder reaches upstream with the real token; an undeclared path, another guest's placeholder, no bearer, and a sign-in step from a run guest are refused with nothing sent.
- `TestPlanRedactsTheInjectedToken` (CLK-4): a provider that echoes the token in a header and across body chunks returns it redacted.
- `TestPlanRefreshSwapsBackToPlaceholders` (CLK-7): the refresh goes out with the real refresh token, the new login is stored before the answer is released, and the guest gets only its placeholders.
- `TestPlanRefreshRunsOneFlight`: concurrent refreshes from two guests make one exchange, and each guest gets its own placeholders.
- `TestPlanUnmatchedAnswerStopsUntilRequalified` (CLK-7): an undeclared field, a missing account, or another account on a refresh is dropped and stops the route, with no further request sent. `Resume` refuses it, a restart keeps it, and a new declaration version lifts it.
- `TestPlanRefusedLoginStopsUntilResumeOrSignIn` (CLK-7): a declared refused code stops the route; `Resume` or a new sign-in lifts it. An undeclared 400 or a 500 is dropped and stops nothing.
- `TestPlanSignInSetsTheLogin` (CLK-7, PLN-5): the device step carries no credential, the code exchange's redirect is rewritten, and only that sign-in guest is `SignedIn`.
- `TestPlanStaleRefreshAnswerStopsNothing` (CLK-7, from the Security review): a refresh answer that arrives after `Remove` or a new sign-in (good, refused or out of shape) is dropped, not committed, and stops nothing.
- `TestPlanCancelledRefreshStillCommits` and `TestPlanRefreshAnswerWithoutARefreshTokenKeepsTheStoredOne` (CLK-7, from the L3 review): a guest that cancels mid-refresh does not lose the rotated token, and an answer that omits the optional refresh token keeps the stored one.
- `TestPlanClerkHoldsOneSlot` (CLK-1): a store sealed for another plan, or under another key, is refused.
- `TestPlanStopHeldWhenTheSlotCannotRecordIt`: a failed slot write still stops the route.

**Usage estimate:** about 120k tokens per slice.
