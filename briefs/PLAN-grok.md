# PLAN-grok: Grok (xAI) plan route on the model clerk

Work item #1378. Tier A. Re-briefed 2026-10-29 onto the model clerk (CLK-7); the 2026-10-17 brief targeted `broker/provagent` and `broker/egress`, which are old core (D-139) and frozen. Grok qualifies after Codex and Muse (D-135); the order blocks nothing, so this row may run as soon as its needs are met.

**What carries over.** D-117: terms verdict `allowed` (x.ai/legal/terms-of-service, read 2026-10-13; the credential-sharing clause does not reach the owner's own box), the clerk holds the login, plan login only, no API key (Mark, 2026-10-14, cmsg_01R63S2yrPkq32thy8WQCuvDToGvZ2vEYNyb3st7AwrJwn and cmsg_01R63S2yrPkq32thy8WQCuvDYTgmCCEorhYYFX8R3HrbkN). Under CLK-7 that is mode `permitted`. No Grok-specific criteria beyond CLK-7. PR #2439 (old core) declared the route gated until qualified; nothing of it is reused.

**Needs.** PLAN-muse slice (a), PLAN-slots (`briefs/PLAN-muse.md`): several plan logins in one model clerk, owner and sign-in socket calls that name their plan. Slice (b)'s wiring also needs #3927's Grok slice. If PLAN-muse (c) added `Require` settings or a second `Body` format, reuse them; this row adds neither unless its capture demands it.

**What is not known.** Nothing of Grok Build's (`grok`) traffic has been measured. The declaration is a measured artifact, so it waits for slice (a) below, which needs Mark's own Grok plan.

**Acceptance tests:** listed per slice below; a capture slice has none (a measurement record).

## Slice (a), PLAN-grok-capture: measure Grok Build on Mark's plan

Needs Mark: a signed-in Grok plan, in a supervised session, as S8-live (#809) did for Codex. No product code. Pin the CLI version (headless `grok -p`, `--no-auto-update`; docs.x.ai/build/cli/headless-scripting), run it behind a recording forwarder, and write `spikes/PLAN-grok-capture/RESULT.md` with: every host, method and path for model calls, reads, refresh and sign-in; one model request body per turn kind with keys and item types (redacted); the token answer's exact fields and kinds; where the account ID is; the refresh body's keys; the refused-login error codes; quota or usage headers and their windows; how its sign-in prints its link and code; its cloud, remote, telemetry and auto-update switches (D-138). Synthetic or redacted values only in the file.

**Requirement IDs (a):** CLK-7, HLD-3.

**Scope (a):** `spikes/PLAN-grok-capture/` (new), this brief.

**Acceptance tests (a):** none: a measurement record. Each item is filled or marked `not observed` with the step tried.

**Stop and escalate after (a)** if the account is named nowhere the clerk can read, or the sign-in is neither a device code nor a code exchange (for example a pasted API key or a browser cookie): each is a design change, not a declaration.

## Slice (b), PLAN-grok-route: the Grok declaration and wiring

1. **`plan.Grok(guard)`** in `broker/clerk/plan`, from the capture, with `Mode: Permitted` and `Version: "grok-<cli version>-1"`; **`run.GrokSignIn()`** with `From: "xAI"`.
2. **Pool** (RES-5): from the captured headers; none gives no reading, recorded in ASSUMPTIONS.
3. If the capture shows a request format the declared `Body` shapes do not cover, add it with the same refusals (hosted tools, remote content, server-side state); over about 400 lines, split first.
4. **Wire it:** `declarations(guard)` in `agentos-clerk-model` gains `plan.Grok`. Wiring is the listing (HLD-3), so it lands only after #3927's Grok slice (the Grok guest image and agentosd's Grok sign-in machine) has merged.

**Requirement IDs (b):** CLK-1, CLK-3, CLK-4, CLK-7, PLN-5, RES-5.

**Scope (b):** `broker/clerk/plan/` (`plan.go`, `plan_test.go`, `body.go` and `body_test.go` only under item 3, `ASSUMPTIONS.md`), `broker/clerk/run/` (`plansignin.go`, `plansignin_test.go`, `ASSUMPTIONS.md`), `broker/cmd/agentos-clerk-model/main.go`, this brief.

**Acceptance tests (b),** in `broker/clerk/plan/plan_test.go` unless named:
- `TestGrokDeclarationValidates` (CLK-7, CLK-4): `plan.New` accepts `plan.Grok`; no forbidden header or prefix, no hosted body key, mode `permitted`.
- `TestGrokInjectsOnlyAtDeclaredEndpoints` (CLK-3): the captured model call reaches upstream with the real token; an undeclared path or host is refused with nothing sent.
- `TestGrokRefreshSwapsBackToPlaceholders` (CLK-1, CLK-7): a captured-shape refresh answer returns only placeholders; one extra field stops the route `unswappable`.
- `TestGrokRefusedLoginStops` (CLK-7): a captured refused-login code stops the route `refused-login`; another 400 stops nothing.
- `TestGrokPlaceholdersDoNotCrossPlans` (CLK-1): a Codex or Muse placeholder at Grok's endpoint is refused with nothing sent.
- `TestGrokPoolReading` (RES-5).
- `broker/clerk/run/plansignin_test.go::TestGrokSignInShowsXAIsPageAndCode` (PLN-5, CLK-7).

**Revert mutants (b):** add an endpoint not captured; forward a token field unswapped; treat a bare 400 as refused.

**Threats Security must check.** A captured header or prefix that passes a credential; a refresh field that carries a credential unswapped; cross-plan placeholder resolution.

**Guard files:** none (no new package). If one must change, stop and say so on #1378.

**Conflict (D-111), 2026-10-29 19:30Z.** Same files as PLAN-muse (a) and (c): build after each has merged, never beside them.

**Not here.** The Grok guest itself (image, inbound API, configuration template with cloud and remote features off, D-138), agentosd's per-plan sign-in machine and the qualification run (HLD-3, HLD-6): #3927.

**Usage estimate:** (a) one supervised session with Mark; (b) about 90k tokens. Builder model: strongest (tier A). Reviews: L3 and Security.
