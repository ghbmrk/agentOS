# REV-LOW-tools-b: srclint build-text tags, lookup next-id fetch order, reviewpacket brief source, difflines inter-hunk context

Board row: #5846 (tier C, lane:primary, class:release). Source: findings 16, 17, 20 and 22 of #4400 (the 23-Low review, 2026-11-01); finding text and cited lines are in #4400's body. Usage estimate: 40k tokens.

## Requirement
- **16 srclint:** a stale `-tags` string in non-build text (an echo, a message) must not authorize a lint tag.
- **17 lookup:** `next-id` reads `origin/main` and the PR heads after the fetch, so a fetch that advances main never leaves an occupied ID as next.
- **20 reviewpacket:** a head lacking its brief keeps the working-tree fallback, labelled in the packet with its source; a brief at head still wins.
- **22 difflines:** the `-U0` diff passes `--inter-hunk-context=0`, so a configured `diff.interHunkContext` cannot fuse hunks and print unchanged lines `in-diff`.

## Design
- srclint: `-tags` counts only on a line that runs `go build|test|vet|run|install|list|generate` or sets `GOFLAGS=`. Narrower than the finding's "read validated configuration", which would need a YAML and shell parser; the line rule rejects the stale-text case and keeps every current build.
- lookup: call `fetch_heads` first, then `tree_ids`; a fetch failure already raises `Failed`.
- reviewpacket: `find_brief` returns `(path, text, source)`; the Brief section prints the source.
- difflines: one added flag.

## Scope (files)
- In scope: `tools/srclint.py`, `tools/lookup.py`, `tools/reviewpacket.py`, `tools/difflines.py`, `tests/test_srclint.py`, `tests/test_lookup.py`, `tests/test_specslice.py` (reviewpacket's tests), `tests/test_difflines.py`, this brief.
- Out of scope: findings 19, 21, 23 (#4400); `tools/ASSUMPTIONS.md` (held while #5838 is open).

## Acceptance tests
**Acceptance tests:** `test_tag_set_comes_from_the_builds` (stale echo and message text), `NextIdFetchOrderTest` (fetch advancing main; fetch failure), `test_brief_absent_at_head_falls_back_to_the_checkout_and_says_so` and `test_brief_at_head_wins_over_a_different_checkout_brief`, `test_configured_inter_hunk_context_does_not_fuse_hunks`.
