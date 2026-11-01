# TOOL-lookup: session lookup helpers

**Goal.** Three lookups sessions kept redoing by hand, as subcommands of one tool, `tools/lookup.py` (standard library and git; open PRs by REST through `gh api`, as `tools/reviewpacket.py` does):

1. `next-id`: the next free decision ID, counting IDs that open PRs' heads add to DECISIONS.md or `decisions/` as well as main's, and naming any ID held twice (five PRs took D-245 in one week). `--range LO[-HI]` keeps to a lane's block (D-247).
2. `ci-why`: the failure lines of a saved job log (Go `--- FAIL` with its message lines, `FAIL`, `panic:`; unittest `FAIL:`/`ERROR:` with the exception line; `##[error]`).
3. `conflicts`: open PR heads that no longer merge cleanly onto their base, by `git merge-tree --write-tree`, with the conflicted paths.

**Requirement IDs:** none; PLAN.md tooling, not SPEC behaviour.

**Declared scope:** `tools/lookup.py`, `tests/test_lookup.py`, this brief. No AGENTS.md pointer (word budget, D-152); the tool's docstring is its documentation.

**Guard files:** none (no broker package; `tools/` is tier C).

**Acceptance tests:**
- `tests/test_lookup.py::NextIdTest` — table rows only (not prose mentions), `decisions/D-N.md` files, a PR's claim is its head's IDs minus main's, a collision names both holders, `--range` keeps to its block and fails when full. Catches: next-id counting prose, missing open-PR claims, or a lane's ID taken from the other block.
- `tests/test_lookup.py::CiWhyTest` — Go and unittest failures with their message lines, timestamps stripped, a clean log prints nothing. Catches: a failure line dropped or a passing line shown.
- `tests/test_lookup.py::ConflictsTest` — a head touching other files merges clean; one editing the same lines names the path. Catches: a false clean or a false conflict.

**Usage estimate:** one Opus session, under 80k.
