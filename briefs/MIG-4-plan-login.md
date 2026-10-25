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

**Slice (b), MIG-4-plan-login-b: the guest's model endpoint and metering** (#3104 comment 6397037553).
1. **Body schema** (`broker/clerk/plan/body.go`). The responses body is part of the plan's declaration (`Declaration.Body`), so it sits beside the rest of the measured route rather than in `broker/clerk/model`. It is the old core's `checkResponses`: declared keys, input types and content types; tools only where the CLI declares them, all client-side; `store` forced off; hosted-tool keys refused at `New`; no remote content source.
2. **Metering** (`broker/clerk/plan/meter.go`, `broker/clerk/model`). `Do` takes the model clerk's `Meter`, which admits a checked model call before it is sent and is settled once from the stream's reported usage and the answer's pool headers (`Declaration.Pool`). `model.Clerk` gains `Admit` and `Admission.Settle`; `Call` uses them.
3. **Listener** (`broker/clerk/run/plan.go`). `ListenPlan` and `ServePlan` serve one guest's provider API over HTTP on a socket that admits only its uid, charged to the plan and route it is built with.
Also carries #3105's follow-ups: the `forbiddenPrefix` test case and the `gen` comment. #3110 (pin `client_id` and `scope`) needs a Codex capture and stays queued.

**Scope (b):** `broker/clerk/plan/` (`plan.go`, new `body.go`, `meter.go`, `body_test.go`, `plan_test.go`, `ASSUMPTIONS.md`), `broker/clerk/model/` (`model.go`, `model_test.go`, `ASSUMPTIONS.md`), `broker/clerk/run/` (new `plan.go`, `plan_test.go`, `ASSUMPTIONS.md`), this brief. No guard file changes: the three packages are already `parser` lines, and `clerk/run` is wiring in `core.txt`.

**Acceptance tests (b):**
- `TestPlanModelBodyHeldToDeclaredShape` (PLN-5, CLK-7) in `broker/clerk/plan/body_test.go`: a request in the measured Codex shape (built in the test from the declaration, #809) passes with `store` forced off; each hosted, undeclared or remote shape is refused with nothing sent and nothing admitted.
- `TestPlanDeclarationRefusesAHostedBody` (CLK-7, CLK-4): a hosted key or tool type, no body shape, or a response prefix that could pass a forbidden header is refused at `New`.
- `TestPlanModelCallIsMeteredOnce` (LOG-7, RES-5): the meter sees the checked body before sending, is settled once with the reported usage and the pool reading, and a refused or missing meter sends nothing.
- `TestPlanModelCallSettlesAsItEnded` (LOG-7): a cut stream, an error status, no figure, an unreadable or too-long event, an encoded answer and a refused dial each settle once, as they ended.
- `TestPlanPoolReading` (RES-5): the tightest window per mille, reset in ms, a reached limit as full, an unreadable window as none.
- `TestAdmittedCallIsSettledOnce`, `TestCountRoundsUp` (LOG-7) in `broker/clerk/model/model_test.go`.
- `TestPlanGuestEndpointMetersEachCall` (PLN-5, CLK-7, LOG-7, RES-5) in `broker/clerk/run/plan_test.go`: over the socket, a call is metered into the kernel's log with its pool reading and no real token reaches the guest; a call past the cap is 429 and never sent. `TestPlanStatusFromDetail` (CLK-4).

**Slice (c), MIG-4-plan-login-c: sign-in and the owner calls** (#3104 comment 6397037553), `broker/clerk/run/plansignin.go`. It ports `provagent/signin.go` onto the plan login clerk.
1. **Mode** (`plan.Declaration.Mode`): `permitted`, `unconfirmed` or `not-allowed`, the read of the provider's terms (CLK-7); `New` refuses any other. Codex is `permitted`.
2. **Sign-in.** `PlanHost.Begin` starts the CLI's device-code sign-in through `SignInWorkers`, the guest host's interface (#2780(b)), as a fresh sign-in guest (`BeginSignIn`) whose only way out is its own endpoint (`ServePlan`). It returns the provider's own page (never the printed link), the code printed after a declared link, and whom the code is from. Success is only `SignedIn` for that guest; an exit, no code in time, an undeclared link or the owner's wall ends it as failed or timed out. The sandbox is destroyed and the guest forgotten on every path. One sign-in waits at a time.
3. **Owner calls** on the model clerk process's owner socket (`ListenPlanOwner`, owner uid only): `planbegin`, `planstate` (mode, signed in, stop, the waiting page and code, how the last sign-in ended; no token), `planresume` (`Login.Resume`; `requalify` for an unswappable stop), `planremove` (ends a waiting sign-in, then `Login.Remove`).
4. **Mode gate** (`PlanGuest.gate`, before anything is read or sent): `permitted` is open; `unconfirmed` serves its sign-in guest and otherwise only while `Consent()` stands, read at each request; `not-allowed` starts no sign-in and serves nothing. The kernel records consent and pause (KEY-4, CH-11); `cmd/agentosd` wires both (#2780(b)).

**Scope (c):** `broker/clerk/run/` (new `plansignin.go`, `plansignin_test.go`; `plan.go`, `plan_test.go`, `ASSUMPTIONS.md`), `broker/clerk/plan/` (`plan.go`, `body_test.go`), this brief. No guard file changes.

**Acceptance tests (c),** in `broker/clerk/run/plansignin_test.go`:
- `TestPlanSignInShowsTheProvidersPageAndCode` (PLN-5, CLK-7): the owner gets the provider's page and the printed code with its provider; the CLI's code exchange through its endpoint signs in; the sandbox is destroyed and the guest forgotten.
- `TestPlanSignInSucceedsOnlyByTheClerksRecord` (CLK-7): a stored login and a CLI exit are not success; no code, an undeclared link, a failed start or the wall end it; a second sign-in is busy.
- `TestPlanModeGate` (CLK-7): `not-allowed` starts nothing and serves nothing; `unconfirmed` signs in without consent, refuses runs until consent, and stops at its withdrawal; nothing refused is sent.
- `TestPlanOwnerSocket` (CLK-7, CLK-4): begin, state, remove and resume over the owner socket; an unswappable stop answers `requalify` and starts no sign-in.
- `TestPlanSignInPromptCode`, and `TestPlanDeclarationRefusesAHostedBody` gains no mode and an unknown mode.

**Usage estimate:** about 120k tokens per slice.
