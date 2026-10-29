# PLAN-muse: Muse (Meta) plan route on the model clerk

Work item #1379. Tier A. Re-briefed 2026-10-29 onto the model clerk (CLK-7); the 2026-10-17 brief targeted `broker/provagent` and `broker/egress`, which are old core (D-139) and frozen. Muse qualifies before Grok (D-135), so this brief also carries slice (a), the multi-plan slots both rows need. PLAN-grok (#1378) reuses (a) and follows this brief's shape.

**What carries over.** D-117: terms verdict `allowed`, the clerk holds the login, plan login only, no API key (Mark, 2026-10-14, cmsg_01R63S2yrPkq32thy8WQCuvDToGvZ2vEYNyb3st7AwrJwn and cmsg_01R63S2yrPkq32thy8WQCuvDYTgmCCEorhYYFX8R3HrbkN). Under CLK-7 that is mode `permitted`. Contributor mode off (Mark, 2026-10-19, cmsg_01R63S2yrPkq32thy8WQCuvDCCENG4PA91Kpi8JKSywhDi; D-132 item 4; #1379 comment 6267616965), now CLK-7's "Muse requires Contributor mode off" bullet. The terms' two criteria (#1379): 4(f) only the owner's own login; 4(p) outgoing actions say they are automated.

**What main has.** `broker/clerk/plan` holds one plan login per `Login`, bound to a `Declaration` (`plan.Codex`, measured on Codex CLI 0.162.1, #809). `broker/clerk/run` serves the guest's endpoint (`ServePlan`) and the owner calls (`planbegin`, `planstate`, `planresume`, `planremove`) for one `PlanHost`. `broker/cmd/agentos-clerk-model` opens one slot (`plan-codex`) with `plan.Codex`. `run.PlanOwner`, the owner side's caller, has no production caller yet (`cmd/agentosd` wires it in #2780(b)).

**What is not known.** Nothing of Muse Code's traffic has been measured: hosts, paths, request body format (OpenAI Responses or another), token answer fields, whether it has an `id_token` and where the account is named, refused-login codes, quota headers, how the sign-in prints its link and code, and where Contributor mode can be read. `plan.Declaration` is a measured artifact; writing it from guesses gives a route that is either wrong (it stops `unswappable` at first use) or loose. So the declaration waits for a capture, slice (b), which needs Mark's own Muse plan.

**Acceptance tests:** listed per slice below; a capture slice has none (a measurement record).

## Slice (a), PLAN-slots: one model clerk, several plan logins

Capture-independent; build now, before #2780(b) wires `PlanOwner`, so `cmd/agentosd` is wired once.
1. **One `Login` per wired declaration**, each in its own sealed slot `plan-<name>` (the Codex slot keeps its name, so a stored login survives). `agentos-clerk-model` builds them from one list, `declarations(guard)`, which holds only `plan.Codex` until slice (c). A declaration on that list is a qualified route (HLD-3): a plan is listed only once a release wires it, so no separate qualification flag is needed.
2. **Owner calls name their plan.** Every `plan*` call carries `{"plan":"<name>"}`; an unknown name is refused (`plan-unknown`) with nothing done. `run.PlanOwner`'s methods take the plan name. `ServePlanOwner` serves a set of `PlanHost`s keyed by name, each with its own `SignInPrompt`, and the API-key calls on the same socket are unchanged. One sign-in waits at a time per plan.
3. **Nothing crosses plans.** A placeholder minted by one plan's `Login` resolves at no other (each `Login` mints its own); a stop, consent or removal of one plan leaves the others as they were (CLK-7 Control: pause and stops are per plan).

**Requirement IDs (a):** CLK-1, CLK-7, PLN-5.

**Scope (a):** `broker/cmd/agentos-clerk-model/main.go` (and its test), `broker/clerk/run/plansignin.go`, `broker/clerk/run/plansignin_test.go`, `broker/clerk/run/ASSUMPTIONS.md`, this brief.

**Acceptance tests (a):**
- `broker/clerk/run/plansignin_test.go::TestPlanOwnerCallsNameTheirPlan` (CLK-7): with two plans served, begin, state, resume and remove act on the named plan only; an unknown or missing name is refused and changes nothing. Fails if a call falls through to a default plan.
- `broker/clerk/run/plansignin_test.go::TestPlanPlaceholdersDoNotCrossPlans` (CLK-1): a guest's placeholder from plan A sent to plan B's endpoint is refused with nothing sent upstream.
- `broker/clerk/run/plansignin_test.go::TestPlanStopsArePerPlan` (CLK-7): an unswappable or refused-login stop, a removal and a withdrawn consent on one plan leave the other serving.
- `broker/cmd/agentos-clerk-model` test `TestPlanSlotsPerDeclaration` (CLK-1): each wired declaration opens `plan-<name>`; an existing `plan-codex` slot still opens signed in; a slot sealed for another plan starts that plan signed out and leaves the others alone.

**Revert mutants (a):** drop the plan-name check (default to the first host); share one `Login` across two declarations; key the slot by a fixed name.

## Slice (b), PLAN-muse-capture: measure Muse Code on Mark's plan

Needs Mark: a signed-in Muse plan with Contributor mode off, in a supervised session, as S8-live (#809) did for Codex. No product code. Pin the CLI version, run it with a recording forwarder in front of its configured base URL, and write `spikes/PLAN-muse-capture/RESULT.md` with: every host, method and path used for model calls, reads, refresh and sign-in; one model request body per turn kind with keys and item types (redacted); the token answer's exact fields and kinds; where the account ID is (an `id_token` claim or an account read); the refresh body's keys; the refused-login error codes (from the CLI's own handling); quota or usage headers and their windows; how `muse login` prints its link and code; the endpoint and field that report Contributor mode, read with it on and off; the CLI's cloud, remote, telemetry and auto-update switches (D-138); and the inbound API candidate (muse-code-sdk driving `muse serve`, #1379 comment). Synthetic or redacted values only in the file.

**Requirement IDs (b):** CLK-7, HLD-3.

**Scope (b):** `spikes/PLAN-muse-capture/` (new), this brief.

**Acceptance tests (b):** none: a measurement record. Each item above is filled or marked `not observed` with the step tried.

**Stop and escalate after (b)** if any of these hold, because each is a design change, not a declaration: Contributor mode cannot be read from any provider answer the clerk can request (CLK-7 says a run refuses while it is on, so an unreadable setting is a spec-gap for L1); the account is named nowhere in a token answer or a read the clerk can make; the CLI's sign-in is not a device code or code exchange.

## Slice (c), PLAN-muse-route: the Muse declaration, its setting gate, and wiring

Needs (a) and (b).
1. **`plan.Muse(guard)`** in `broker/clerk/plan`, from the capture: endpoints, token fields, account claim, refused codes, refresh keys, redirect rewrite, header lists, `Body`, `Pool`, `Mode: Permitted`, `Version: "muse-<cli version>-1"`. **`run.MuseSignIn()`**: links, page, `From: "Meta"`.
2. **Required settings** (CLK-7 Contributor-mode bullet). `Declaration` gains `Require []Setting`, each a declared `Read` endpoint, a JSON path in its answer and the value it must hold. The clerk makes the read itself with the real token, never through a guest: after a sign-in's code exchange commits, and each time it issues a guest a token set (a run's start, `Login.Guest`). A value that differs, is missing or unreadable refuses that run with a closed detail `plan-setting` and no retry (the guest gets no token set), and `planstate` reports it so ONB-9's line can tell the owner what to change. It is not a route stop: the next run reads again, so turning Contributor mode off at Meta needs no `PLAN Muse ON`. `plan.Codex` declares none.
3. **Pool sizing** (RES-5): Muse's pool is read from its declared headers, which carry the allowance that applies to the account as set, so with Contributor mode off the reduced allowance is what is read. If the capture shows no usage headers, the route has no pool reading; record that in ASSUMPTIONS rather than invent a size.
4. **4(f), only the owner's own login:** already the clerk's shape (one slot per plan, per-guest placeholders, an account change kills old placeholders, MIG-4-plan-login-a1, a2). Tested here on the Muse declaration.
5. **4(p), automated nature disclosed:** satisfied on every route by CH-21's rule that the box tells everyone else it is an automated assistant in names, signatures and call openings, which the kernel renders whatever guest planned the step. No Muse-specific code; record it as an ASSUMPTIONS row citing CH-21.
6. **Wire it:** `declarations(guard)` in `agentos-clerk-model` gains `plan.Muse`. Wiring is the listing (HLD-3), so this lands only with (b)'s capture behind it.
7. If the capture shows a request format other than OpenAI Responses, `Body` gains that format as a second declared shape with the same refusals (hosted tools, remote content, `store`-like server-side state). If that adds more than about 400 lines, split it into its own slice before building.

**Requirement IDs (c):** CLK-1, CLK-3, CLK-4, CLK-7, PLN-5, RES-5, ONB-9.

**Scope (c):** `broker/clerk/plan/` (`plan.go`, `plan_test.go`, `body.go` and `body_test.go` only under item 7, `ASSUMPTIONS.md`), `broker/clerk/run/` (`plansignin.go`, `plansignin_test.go`, `ASSUMPTIONS.md`), `broker/cmd/agentos-clerk-model/main.go`, this brief.

**Acceptance tests (c),** in `broker/clerk/plan/plan_test.go` unless named:
- `TestMuseDeclarationValidates` (CLK-7, CLK-4): `plan.New` accepts `plan.Muse`; it declares no forbidden header or prefix, no hosted body key, and mode `permitted`.
- `TestMuseInjectsOnlyAtDeclaredEndpoints` (CLK-3): the capture's model call, built from the declaration, reaches upstream with the real token; an undeclared path or host is refused with nothing sent.
- `TestMuseRefreshSwapsBackToPlaceholders` (CLK-1, CLK-7): a refresh answer in the captured shape returns only placeholders; one extra field stops the route `unswappable`.
- `TestMuseOnlyOwnersLogin` (4(f), CLK-1): another guest's placeholder, a placeholder minted before a sign-in to another account, and a Codex placeholder are refused with nothing sent.
- `TestPlanRequiredSettingRefusesRun` (CLK-7): with the setting read as Contributor on, missing, or the read failing, `Guest` issues no token set and the detail is `plan-setting`; read as off, it issues one; the route is not stopped, and the next run reads again. Fails if the read is skipped or cached past a run's start.
- `TestPlanRequiredSettingCheckedAtSignIn` (CLK-7): a sign-in whose account reads Contributor on commits the login but `planstate` reports the setting and no run starts.
- `TestPlanRequiredSettingNotGuestReachable` (CLK-3): a guest cannot make the setting read or supply its answer.
- `TestMusePoolReading` (RES-5): the captured headers give the reading; none gives no reading.
- `broker/clerk/run/plansignin_test.go::TestMuseSignInShowsMetasPageAndCode` (PLN-5, CLK-7): the printed link and code from the captured format give Meta's page and code.

**Revert mutants (c):** skip the setting read at a run's start; accept a missing setting value; forward a refresh field unswapped; let a guest endpoint reach the setting read.

**Threats Security must check.** A guest steering the setting read or its answer; a Contributor-on account running because the read failed open; cross-plan or cross-account placeholder resolution; a captured header or prefix that passes a credential.

**Guard files (all slices):** none. `broker/clerk/plan`, `broker/clerk/run` and `broker/cmd/agentos-clerk-model` exist and are classed; no new package. If the builder finds a guard file must change (`tools/trusted_base_parsers.txt`, `tools/trusted_core.txt`, `tools/g1_scope*.txt`), stop and say so on #1379.

**Conflict (D-111), 2026-10-29 19:30Z.** No open PR touches `broker/clerk/plan` or `broker/clerk/run/plansignin*`. #3861 may touch `agentos-clerk-model` tests: check its files before starting (a). (a) should merge before #2780(b) starts; tell the coordinator if #2780(b) is already building.

**Not here.** The Muse guest itself (its image, inbound API, configuration template with cloud and remote features off, D-138, PLN-5 declaration) and its qualification run (HLD-3, HLD-6). D-142 failover between plan guests is the kernel's.

**Usage estimate:** (a) about 70k tokens; (b) one supervised session with Mark; (c) about 110k (split item 7 if it grows). Builder model: strongest (tier A). Reviews: L3 and Security per slice.
