# PLAN-muse: Muse (Meta) plan route as a CAP-11 provider agent (broker-held)

Board row: work item #1379. Tier A (`broker/provagent/declare.go`, egress route wiring). Needs: #1314 (merged), #1377 terms read (done: verdict `allowed`, broker-held, Mark 2026-10-14). Disabled until S8-live (#809) fills the record.

**Why.** An owner with a Meta Muse plan has no plan route. Meta's official CLI is Muse Code (`muse`; `muse login` by device code; installed from dev.meta.ai). Its sign-in is a device code, so the sign-in page relays a code and link, not a pasted artifact (to be confirmed by #809; recorded as an assumption). Muse is a plan login with no API key (Mark, 2026-10-14).

**Requirements:** CAP-11, CRED-5 broker-held, CRED-1, CRED-7, RES-5, OP-8, CAP-9, plus two criteria from the Muse Supplemental ToS (muse.ai/terms, 2026-09-08):
- **4(p) automated nature disclosed.** Outgoing actions made through Muse must say they are automated. The declaration carries the disclosure, and a run whose brief would send an outgoing action refuses unless the disclosure is attached.
- **4(f) only the owner's own login.** The route resolves only the owner's placeholder for the signed-in plan; a guest-supplied or another account's login never resolves.

**Change.** Same shape as PLAN-grok: `Builtins()` gains `muse` (broker-held, `allowed`, terms URL muse.ai/terms, read 2026-10-13, empty CLI version and evidence), an egress `WorkerRouteConfig` for Meta's endpoints from the CLI source (marked unmeasured), declared pools if the endpoints return quota headers. A first-run payment-method refusal from Meta (the CLI refuses until one is attached) maps to the closed reason for a refused plan (no retry).

**Acceptance tests** (`broker/provagent/muse_test.go`, `broker/egress/museroute_test.go`, new): CAP-11: `TestMuseDeclarationValidates`; `TestMuseRefusesUnqualifiedUntilRecordFilled`; `TestMuseQualifiedStubRuns`. CRED-5/4(f): `TestMuseResolvesOnlyOwnersPlaceholder` (another worker's or provider's placeholder is refused); `TestMuseRouteInjectsOnlyAtDeclaredEndpoints`. 4(p): `TestMuseOutgoingActionCarriesAutomationDisclosure` (an outgoing-action brief without the disclosure refuses; fails if the check is removed). CRED-1: `TestMuseTokenResponseSwapsAllCredentialFields`. CRED-7: `TestMuseResultWithCanaryCredentialWithheld`. CAP-9: `TestMuseUsedUpAndRefusedPlanFallBack`.

**Revert mutants.** Drop the qualification check; drop the disclosure check; resolve a placeholder of another worker; leave a token field unswapped; retry after a refused plan.

**Threats Security must check.** Cross-account or cross-worker placeholder resolution; the disclosure being strippable by the brief; an outgoing action sent without disclosure through a path the check does not see; unmeasured lists failing open.

**Scope:** `broker/provagent/declare.go`, `broker/provagent/muse_test.go` (new), `broker/provagent/ASSUMPTIONS.md`, `broker/egress/museroute.go` (new), `broker/egress/museroute_test.go` (new), `broker/egress/ASSUMPTIONS.md`, `briefs/PLAN-muse.md`. Not in scope: `workerroute.go` wiring (after #1857, #2015). **Guard files:** as PLAN-grok; flag allowlist additions (`broker/daemon/arc2_test.go`, `tools/g1_scope.txt`) in the PR.

**Conflict (D-111) at 2026-10-17 00:14Z.** #2015 holds `broker/provagent`. Build after PLAN-grok merges (same files in `declare.go`), and after #2015.

**Usage estimate:** 90k tokens. Builder model: strongest (tier A); two reviews.
