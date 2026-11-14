# KEY-9-reach-b2-cut: cut trusted lines no binary reaches, to make room for b2a and b2b

Board section: Owner channel and approvals (SPEC §10). Work item #5671, split from #5060 (KEY-9-reach-b2). Main sits at D-310's trusted-lines ceiling (59,120 of 59,120 at `fbc6460`, `tools/trusted_base.py measure`), and b2a and b2b each add kernel lines (estimates: b2a about 180, b2b about 120). This row makes that room first, so neither kernel build has to hunt for deletions. It follows MIG-5-dead-cut (#5010, #5011): delete or move code that no main package reaches, with no change in behaviour.

**Requirements:** D-310 (the ceiling), KRN-2 (the trusted base only shrinks). No SPEC behaviour changes.

**Target:** `trusted_base.py measure` at least 350 lines below main's measure at this PR's base. Lines moved into `_test.go` files, into `testdata`, or into a package outside `tools/trusted_core.txt`'s roots and `tools/old_core.txt` count as cut; lines moved between counted packages do not.

**Candidates** (`deadcode ./...` over every main package at `fbc6460`, run in `broker/` with `GOFLAGS=-mod=vendor CGO_ENABLED=0`; sizes are approximate and include doc comments). Re-run at build time; take the cheapest that reach the target.

| Lines | Where | What | Note |
|---|---|---|---|
| ~345 | `broker/backup` | `Open`, `Sections`, `sectionReader`, `decodeManifest`, `parseHeader`, `openFrom`, `opener`, `Rewrap`, `UnwrapTable`, `MemTarget` table methods | The restore side. Tests in `backup` and `kernel/proc` use it, so it moves to an untrusted package (a new one needs its guard files) or into test files; check no planned binary needs it in the core first. |
| ~289 | `broker/clerk` (`exit.go`, `clerk.go`) | the in-process `Exit` and `Mail` (`NewExit`, `NewMail` and their methods) | Used by `clerk/run` and `kernel/sim`, neither a core root. `clerk/run` is in open PR #5662's scope: do not edit its files; leave this candidate unless the move needs no `clerk/run` edit. |
| ~78 | `broker/egress` | `grokroute.go` (`Grok`), `JournalAuditor.Egress`, `refreshFlights.joined` | `provagent/declare.go` still uses `Grok` until #3432 deletes provagent. |
| ~50 | `broker/clerk/seal` | `Store.Replace`, `Store.SetPolicies` | |
| ~46 | `broker/vault` | `faults.go` injectors, `keyFile.unwrap`, `Create` | Fault injection in production code; move to `export_test.go` where only in-package tests use it. |
| ~34 | `broker/journal` | `MemStore` methods, `Decode`, `AttemptKey` | Cross-package test users keep it where it is. |

Not candidates: `kernel/rederive.go` (KRN-6's re-derivation, used by tests and named by the fold's comments), anything in `broker/grants` (open PR #5670), anything in `broker/clerk/run` (open PR #5662), and `broker/kernel/*.go` (kept free for b2a).

**Scope:** the candidate files the builder picks from the table, their tests, the comments and ASSUMPTIONS rows that name what moves, `tools/risk_tier.py` and `broker/daemon/arc2_test.go` only if a new untrusted package is made, this brief.

**Guard files:** none unless a new package is made; then its class in `tools/risk_tier.py` and its import rules in `broker/daemon/arc2_test.go`, both pre-approved here.

**Acceptance tests:** none new: the package removes code. Evidence in the PR body: `trusted_base.py measure` before and after (at least 350 lower), `deadcode` showing each removed function was unreached, and `go build ./...`, `go vet ./...` and the touched packages' tests passing.

**Tier / gate:** tier A (trusted base): L3 and a separate Security accept. One session; estimate 60k tokens.
