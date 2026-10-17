# PLAN-grok: Grok (xAI) plan route as a CAP-11 provider agent (broker-held)

Board row: work item #1378 (Release rows carried from LATER.md). Tier A (`broker/provagent/declare.go`, egress route wiring). Needs: #1314 (merged: provagent, Codex declaration and gate), #1377 terms read (done: verdict `allowed`, broker-held, Mark 2026-10-14). The route stays disabled until S8-live (#809) fills its qualification record, as Codex does.

**Why.** An owner with a Grok plan and no API key has no plan route. xAI's official CLI is Grok Build (`grok`; headless `grok -p`, `--output-format`, `--no-auto-update`; docs.x.ai/build/cli/headless-scripting). Its terms read allows broker-held use (no clause bars automation; the credential-sharing clause does not reach the owner's own box).

**Requirements:** CAP-11 (declaration, not router code), CRED-5 broker-held (placeholders in the CLI, injection at declared endpoints only, CRED-5c consent not needed at `allowed`), CRED-1, CRED-7, RES-5 (declared pools), OP-8, CAP-9 fallback.

**Change.**
- `Builtins()` gains `grok`: broker-held, verdict `allowed`, terms URL x.ai/legal/terms-of-service, read 2026-10-13, headless argv with the brief on stdin as data, declared result file, placeholder shape and sign-in links from the pinned CLI. The CLI version and evidence fields are empty until #809 fills them, so the gate refuses `unqualified`.
- The egress route for xAI: a `PlanRoute` like `Codex()` (declared endpoints, swap positions, request/response header lists, token response fields, refused-login codes). Lists come from the CLI source and are marked unmeasured in `broker/provagent/ASSUMPTIONS.md` and `broker/egress/ASSUMPTIONS.md` until #809 measures them (see PLAN-resolve-fields).
- Pools: whatever quota headers the xAI endpoints return, declared as `Pool{Name, ReadFrom}`; if the CLI reports none, the declaration carries no pool and RES-5 admission treats it as unmetered-by-header (recorded as an assumption, not guessed).
- Nothing in router code, `modelroute` or the gate changes.

**Acceptance tests** (`broker/provagent/grok_test.go`, `broker/egress/grokroute_test.go`, both new): CAP-11: `TestGrokDeclarationValidates` (loads; a credential-shaped value, missing field or unknown custody refuses); `TestGrokRefusesUnqualifiedUntilRecordFilled` (empty version/evidence refuses `unqualified`; fails if the gate is skipped); `TestGrokQualifiedStubRuns` (test-only qualified copy runs a stub end to end). CRED-5: `TestGrokRouteInjectsOnlyAtDeclaredEndpoints` (a placeholder to an undeclared host or position is refused and never resolved); `TestGrokRouteRefusesUndeclaredRefreshField`. CRED-1: `TestGrokTokenResponseSwapsAllCredentialFields` (a canary token field never reaches the worker). CRED-7: `TestGrokResultWithCanaryCredentialWithheld`. CAP-9: `TestGrokUsedUpFallsBack`.

**Revert mutants (each must turn a test red).** Drop the qualification check for grok. Add an endpoint not in the declaration. Pass a token field unswapped. Skip the result scan.

**Threats Security must check.** Injection at a position or host not declared; the worker obtaining the real login via a refresh response field not swapped; a guest choosing the grok declaration to reach another provider's login; the unmeasured header/field lists failing open (they must fail closed).

**Scope:** `broker/provagent/declare.go`, `broker/provagent/declare_test.go` (`TestBuiltinsLoad` asserts two builtins; update the count), `broker/provagent/grok_test.go` (new), `broker/provagent/ASSUMPTIONS.md`, `broker/egress/grokroute.go` (new), `broker/egress/grokroute_test.go` (new), `broker/egress/ASSUMPTIONS.md`, `briefs/PLAN-grok.md`. The shipped egress wiring in `broker/cmd/agentos-egress/workerroute.go` is NOT in scope; it follows once #1857 and #2015 merge (D-111). **Guard files:** `broker/provagent/` and `broker/egress/` are tier A through the core list (`broker/core/core.txt`); if a new file needs adding to the allowlist in `broker/daemon/arc2_test.go` or `tools/g1_scope.txt`, say so in the PR (those are Mark-only merges).

**Conflict (D-111) at 2026-10-17 00:14Z.** #2015 holds `broker/provagent`; #1857 holds `workerroute.go`. Do not start until #2015 merges.

**Usage estimate:** 90k tokens. Builder model: strongest (tier A); two reviews.
