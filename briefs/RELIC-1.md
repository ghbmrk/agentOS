# RELIC-1: delete three relics of superseded designs

Source: the vestigial-debt sweep (`answers/2026-10-24-vestigial-sweep.md` in the project files) and Mark's answer on its card, 2026-10-24 12:11Z: "If deletion is reversible then delete" (cmsg_01R91wiieBzMSvPKFsAJVvuKAFtTNWiK8ju7sC8gNLP4PA). Tier: A (gate files). Usage estimate: 80k tokens.

**Why.** None of these runs or ships, and each was built for a design a later decision replaced. Git keeps them for any future rebuild.

## Requirements

- **RELIC-1-1** The v0.12 publication code (`broker/hint`, `broker/cleanroom`, `broker/pubid`) is deleted. No binary linked it, and SPEC §15 rebuilds publication on the kernel after migration step 5 (PUB-1). The `cr-` machine-name prefix stays reserved in `agentos-egress`.
- **RELIC-1-2** The reviewer-eval harness (`evals/review/`, `tools/revieweval.py`, `tests/test_revieweval.py`; #2166) is deleted. No workflow or process doc ran it.
- **RELIC-1-3** Three spikes for dropped routes are deleted: `spikes/claude-setup-token` (D-140), `spikes/S10-pact` (D-078, superseded by D-139) and `spikes/S8-provider-workers` (CRED-5's worker-held mode, dropped in SPEC Appendix A).
- **RELIC-1-4** Every list that named them drops them: risk tiers (`tools/risk_tier.py`, OPERATING §3), the G2 list, CI's machines job, the soak matrix, `broker/durable/stores.txt`, the plain-name map, the product-name and legacy-ID baselines and `tools/ci_split.py`'s weights. Also carried: #2986's two doc findings (the G2 list's syntax header, and `tools/ASSUMPTIONS.md` D27/D29).

**Acceptance tests:** RELIC-1-1..3 `go build ./...` and `go vet ./...` in `broker/`; RELIC-1-4 `tests/test_risk_tier.py` (`test_every_tier_a_package_exists`, `test_operating_tier_a_list_agrees_with_tier_a_broker`), `tests/test_g1_scope.py` (`test_every_entry_exists`), `tests/test_ci_split.py` (`test_every_weighted_package_exists`), `tests/test_ci_scope.py`, `tests/test_product_name.py`, `tests/test_doclint.py`, `broker/loops` `TestThePlainNameMapCoversEveryLoop7Subject`, `tools/trace.py --ratchet`.

**Guard files:** `tools/risk_tier.py`, `docs/OPERATING.md` §3 (tier list only), `tools/g1_scope_g2.txt`

## Scope

The deleted paths above, plus `.github/workflows/ci.yml`, `.github/workflows/soak.yml`, `broker/cmd/agentos-egress/main.go`, `broker/cmd/agentos-egress/storedgrants_test.go`, `broker/durable/stores.txt`, `broker/loops/plainname.go`, `docs/OPERATING.md`, `docs/security/provider-worker-feasibility.md`, `tests/product_name_baseline.json`, `tests/test_ci_scope.py`, `tests/test_ci_split.py`, `tests/test_g1_scope.py`, `tools/ASSUMPTIONS.md`, `tools/assumptions_legacy_ids.txt`, `tools/ci_split.py`, `tools/g1_scope_g2.txt`, `tools/risk_tier.py`, `briefs/RELIC-1.md`.
