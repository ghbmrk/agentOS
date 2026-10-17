# CX-name-case-hostchange: product name in broker/hostchange and the owner's guide

Board row: #1668 (split from #1305, CX-name-case batch 1). Reference diff: commit 6eb8dee on `pkg/codex-cx-name-case-prose-1`.

**Goal:** product-name prose `Agent`+`OS` becomes `agentOS` in `broker/hostchange` and in `docs/owners-guide.md`, which that package pins by heading and text. No identifier, path or behavior changes.

**Requirement IDs:** none of SPEC's; the rule is CX-name-case (`tests/test_product_name.py`).

**Acceptance tests:**
- `tests/test_product_name.py::ProductNameTest::test_tracked_text_has_no_new_capitalized_product_name`: the touched files carry no old-name line beyond their baseline, and the baseline entries for these three files are removed, so a reintroduced old-name line fails.
- `broker/hostchange` `go test ./broker/hostchange/`: the renamed headings (`StartHeading`, `ChangesHeading`) and the recovery-prompt text still match `docs/owners-guide.md`; catches renaming one side only.

**Scope:** `broker/hostchange/hostchange.go`, `broker/hostchange/hostchange_test.go`, `docs/owners-guide.md`, `tests/product_name_baseline.json`, this brief. The owner's guide is in scope because `hostchange_test.go` reads its headings: renaming the constants alone fails that test.

**Guard files:** none (no package added).

**Tier:** `tools/risk_tier.py` prints B (hostchange is a tier B broker package); the issue's "tier A" label predates that.

**Usage estimate:** small, under 50k tokens.
