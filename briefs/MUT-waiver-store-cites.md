# MUT-waiver-store-cites: record reasons cite statements, not line numbers

Board section: Defects and later findings on surviving packages. Work item #5787, a release finding on #5780 (MUT-waiver-store), Security fix-list 6885616632.

**Invariant.** A record entry's reason stays readable against the code after lines move: it names the statement, function or field it rests on, never a `file:line`, `:line` or cover-block `line.col` position.

**Build.** Rewrite each such citation in `broker/clerk/run/MUTANTS-EQUIVALENT` as the statement text or the function name it pointed at, checked against main (some had already drifted: the `secrets.go:27`, `:30` and `:303-307` citations point into `broker/clerk/secrets.go`, where those statements now sit at 29, 32 and 300-304). Reason text only: every other field, `accepted` included, is unchanged (`test_the_clerk_run_record_holds_the_5743_proofs` pins the `accepted` values, and `tests/test_mutgate.py` is #5786's scope). Each rewritten entry shows as new in this PR in mutgate's summary, so its review reads the new text as a proof change, as the issue asks.

**Out of scope:** the optional `waive` warning on a `:<digits>` citation (it would touch `tools/mutgate.py`, a gate file in the serial mutgate lane).

**Scope:** `broker/clerk/run/MUTANTS-EQUIVALENT`, this brief.

**Acceptance tests:**
- MUT-waiver-store-cites: `tests/test_mutgate.py::Record::test_every_record_in_the_repository_resolves` (the rewritten record still loads and every entry resolves at the head), and `grep -nE '\.go:[0-9]|:[0-9]+[ ,.;)-]|[0-9]+\.[0-9]+ to [0-9]' broker/clerk/run/MUTANTS-EQUIVALENT` prints nothing (no line citation left).

**Done:** CI green; both checks above pass.
