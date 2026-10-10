# SIM: fewer, stronger parts

Board section: Simplification (2026-10-10). Decision: D-095. Analysis: the simplification thread's two files (architecture review of main at `3436a3d` and its holistic companion), summarized here so each package stands alone.

**Why.** SPEC §9 already describes one primitive: every effect is a journaled intent with "one audit trail, one recovery rule" (OP-5), restart is replay (OP-4), and preconditions are rechecked at dispatch (OP-3). The code drifted from that shape: about 25 packages persist their own state with their own atomic-write and recovery code, FORGET has to reach 11+ of them, "was it right" lives in four vocabularies (two first-write-wins), and owner messages are rendered strings outside the journal. Most open defects (DEL-1 lost reply, the pacer's stale "Cleared", W5-Dc-r17 forget not reaching the hold) and most open follow-up chains (W5-D, W3-forget) are symptoms of that drift. The plan makes §9 literally true and deletes what then becomes redundant, without dropping any acceptance test or SPEC invariant.

**Target shape.** Three parts and one verb:

| Part | Job | Trust |
|---|---|---|
| Broker floor | custody, isolation, grants, recheck at dispatch, STOP, bounds | trusted, named core, tier A |
| Journal | what was intended, authorized, done, observed, judged, erased | trusted; the only durable state |
| Projections | inbox, digest, pacing, hold, learning statistics, attention | untrusted; pure functions of the journal, rebuilt at boot |

The verb is the intent lifecycle: intent, authorized, dispatched, observed, settled, judged.

**Order.** Wave 0 fixes foundation defects and needs no spec change. Wave 1 needs the SIM-sd spec diff for SIM-5 onward; SIM-3 and SIM-4 can start before it. Wave 2 migrates consumers and deletes the duplicates. Each package is one session; tier A packages run on the strongest model.

**Rule for every package.** Deletion is the deliverable as much as the addition: each PR lists the lines, files and BOARD rows it retires. A package that adds a durable format outside the journal is rejected unless SIM-sd lists it as a documented cache.

---

## SIM-gate: the merge gate compares content, not patch-ids (tier C)

**Goal.** `tools/premerge.py` in #692 decides "same" from `git patch-id --stable`, which ignores whitespace: an indentation-only change to a YAML or Python file can flip behaviour (deny to allow) and still report `same` (second external review, 2026-10-10).

**Change.** Compare the reviewed and current diffs exactly: for each file, the pair of blob hashes (base side and head side) of `git diff --raw` after merging main into both, or the byte-exact `git diff` text. Lands as a fix in #692 before it merges, not as a new PR.

**Requirement IDs.** CHG-1 (what merges is what was evaluated). **Acceptance.** `test_premerge.py`: an indentation-only change to a reviewed file reports `changed <file>`; main merged in with no change to the PR's files reports `same`.

**Out of scope.** The main ruleset (required checks, strict up-to-date): a GitHub setting only Mark can change; a decision card asks for it.

**Usage estimate.** Small, under 40k tokens. Tier C.

## SIM-fs: one durable-write helper used everywhere (tier A)

**Goal.** A rename is durable only after the containing directory is fsynced. Seven packages carry their own `writeAtomic` (pubid, update, follow, vault, clock, pubsend, recovery) and five their own `syncDir` (recall, update, agentos-egress, cleanroom, recovery); VM metadata in `vm/vm.go` and `vm/gvisor/gvisor.go` renames with no directory sync, so a power cut can lose a committed metadata write (second external review).

**Change.** One package (for example `broker/durable`) with `WriteFile(path, data, perm)` (temp file in the same directory, write, fsync file, rename, fsync dir) and `SyncDir`. Every listed copy is replaced by it and deleted; the vm rename sites use it. A CI grep fails on `os.Rename` outside the helper unless the line carries a `durable:exempt <reason>` comment.

**Requirement IDs.** OP-4, RES-4. **Acceptance.** `TestWriteFileSyncsDir` with an injected fs that records the fsync order; `TestNoBareRename` (the CI grep). Net lines go down.

**Usage estimate.** Medium, under 100k tokens. Tier A (vault, egress, vm).

## SIM-bound: bounded broker memory and STOP without a history walk (tier A)

**Goal.** The second external review measured 136.6 MiB retained after 5,000 deny-all requests, and STOP traverses the journal under a lock, so STOP's latency grows with history.

**Change.** Find the retention with a heap profile and bound it (evict settled denials from in-memory indexes; they stay in the journal). STOP reads an index of open intents kept current on append, not the history.

**Requirement IDs.** CH-2 (STOP handled by the broker), OP-4 (replay rebuilds the index). **Acceptance.** A benchmark test: retained heap after 50,000 deny-all requests is within a fixed bound of the heap after 5,000; STOP's work is independent of the count of settled intents.

**Usage estimate.** Medium, under 100k tokens. Tier A (journal).

## SIM-sd: L1 spec diff for one log (Mark approves)

**Change to SPEC.** (1) The journal is the only durable source of truth; every other store is a projection rebuilt from it, or a cache named in SPEC with the journal offset it reflects. (2) Owner messages are intents: `owner.inform` with a subject and the subject's revision, rendered at dispatch, so OP-3 drops a message whose subject has moved on. (3) One outcome record per goal, revisable, latest revision wins (OP-7). (4) A learning mechanism is off until it beats the baseline on SPEC §1's objective on independent goals (LOOP-3). (5) FORGET erases in the journal and rebuilds projections (CAP-3).

**Acceptance.** Mark approves the diff. doclint and trace pass. **Usage estimate.** Small, under 40k tokens. Tier B.

## SIM-check: one journal invariant checker (tier A)

**Goal.** Floor invariants are written today as many separate crash-cut and composition tests, and fuzz "Cleared" trusts the target's own PASS lines.

**Change.** A package of predicates over any journal: no effect dispatched without a grant valid at dispatch (OP-3); every dispatched effect ends settled or explicitly uncertain (OP-4); no erased subject readable from any projection (CAP-3); no owner message dispatched with a stale subject revision (after SIM-5). The same checker runs in property tests over generated logs, in CI over the five-journey runs, and at runtime as a STATUS line when it finds a violation.

**Requirement IDs.** OP-3, OP-4, OP-5, CAP-3. **Acceptance.** Each predicate has a generated counterexample journal it rejects and a valid one it accepts; mutants that drop each predicate fail. **Usage estimate.** Medium, under 120k tokens. Tier A.

## SIM-proj: journal snapshots and a projection API (tier A)

**Change.** `Projection` interface: `Apply(record)`, `Snapshot() / Restore(bytes, offset)`. The journal writes periodic snapshots with the offset they reflect; boot restores the latest snapshot and replays the tail. Projections never persist as a source of truth.

**Requirement IDs.** OP-4, RES-4. **Acceptance.** Rebuild from snapshot plus tail equals rebuild from empty, for a generated log (property test); a corrupt snapshot falls back to full replay. **Usage estimate.** Medium, under 120k tokens. Tier A.

## SIM-owner: owner messages are intents (tier A)

**Needs.** SIM-sd, SIM-proj, DEL-1 and PACE-1 merged (#709, #708: the two point fixes this generalizes).

**Change.** The pacer's hold, the digest queue and owner-state held texts become projections over `owner.inform` intents. Quiet hours, urgent classes, eviction priority and held-text visibility (W5-Dc-r13 to r16) become rules in that projection. The W5-D draft PRs stay open as reference; their crash and composition cases are extracted as tests against the projection. `broker/digestqueue`'s own durability, leases and receipts are deleted.

**Requirement IDs.** OP-3, OP-4, OP-9, CH-15. **Acceptance.** A guest reply accepted before a crash is delivered after restart (DEL-1's test, unchanged); a "Cleared" whose subject revised before dispatch is not sent; a forgotten subject's held text is not sent (W5-Dc-r17's case). Net lines go down. **Usage estimate.** Large; split at start if the brief exceeds 20k tokens. Tier A.

## SIM-outcome: one revisable outcome record (tier A)

**Change.** `outcome{goal_id, intent_id, verdict, source, revision}` in the journal; the suite, adoption gate, attention and digest read the latest revision. Delete `change.Outcome`, `loops.Outcome`/`Action` and `grants.OwnerVerdict` in favour of it; remove both first-write-wins paths (`grants/gate.go` "keeps only the first verdict", `loops/harvest.go` "the suite keeps the first"). Evidence counts distinct `goal_id`, not effects.

**Requirement IDs.** OP-7, CHG-1, LOOP-3. **Acceptance.** A verdict revised to wrong after adoption reverts the adoption decision; eight effects from one goal count as one episode. **Usage estimate.** Large, under 150k tokens. Tier A.

## SIM-erase: forget once, in the journal (tier A)

**Needs.** SIM-proj, SIM-check.

**Change.** FORGET erases the subject in the journal (`journal/erase.go`) and rebuilds affected projections; SIM-check's "no erased subject readable" predicate is the test. The per-package forget hooks are deleted as each store becomes a projection. The forget log over backups (W3-forget-b1-5, b1-6) keeps its own row: it governs restores, which a projection does not cover.

**Requirement IDs.** CAP-3. **Acceptance.** The checker finds no erased subject in any projection after forget, after restart, and after a restore. **Usage estimate.** Medium, under 120k tokens. Tier A.

## SIM-core: the trusted core is a named list (tier B)

**Change.** One file lists the core packages (journal, grants, vault, sockets, egress, childproc, verb, guest, meter, guesterr). A CI import check fails when a package outside it imports a core write path other than the journal's `Submit`. `tools/risk_tier.py` reads the list: core = A.

**Requirement IDs.** ARC-1. **Acceptance.** A fixture package that writes grants directly fails the check; `risk_tier.py` rates a core file A and a non-core broker file B. **Usage estimate.** Small, under 60k tokens. Tier B (tools and CI).
