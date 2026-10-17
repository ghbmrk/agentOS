# ONB-spec-text: credential wording (#1424) and the box's own model (#1368)

Tier B (SPEC text). Builder: Sonnet 5.5. Usage estimate: 30k tokens. Needs Mark's approval of the SPEC diff (L1 spec-diff PR).

**Why.** D-115 wrote credential sentences that read as forbidding the designed provider-authentication path (CRED-5, CAP-9). D-113's adoption order (local > plan > more local > API key) needs the box's own model defined and shipped, plan exhaustion to fall back to it, and setup to offer local compute before an API key. One PR: both issues edit REV-6 and §8.1 step 6.

## Requirements
- **#1424** REV-6 and §8.1 step 6 say credentials are never sent to a model as content, a credential reaches only its own provider's declared endpoints as authentication (CRED-5, ADP-10); owner line "Your passwords and keys are never shown to it."; REV-6 limits the claim to credentials the box holds (#1424 comment, Security review of #1436).
- **#1368** New ONB-11 names the box's own model per hardware profile and ships it in the image; step 6 lists Local only first, then plan, local compute, API key; the plan-exhaustion line falls back to the local model; ONB-11 counts a serving local route as allowed for private content (#1368 comment, Potency P-1).

## Acceptance
**Acceptance tests:** none: text-only SPEC change; no requirement gains code, so checks are doclint and the L3 wording review below.

Text-only: no requirement ID gains code. `python3 tools/doclint.py` passes; `python3 tools/risk_tier.py --git origin/main HEAD` prints B or C; a fresh L3 checks the wording against CRED-5, CAP-9, CAP-13, REV-6 and D-113. Failure path: a reader takes "no setting sends credentials to any provider" as forbidding the proxy's injection of a Codex login.

## Scope
`SPEC.md` (REV-6, §8.1 step 6, ONB-11, change log), this brief.
