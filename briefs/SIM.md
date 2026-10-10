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

**Order.** Wave 0 fixes foundation defects and needs no spec change. Wave 1: SIM-check, SIM-proj and SIM-cases need no spec change and can start at once; SIM-owner-hold, SIM-pull, SIM-outcome and SIM-erase need SIM-sd. Wave 2 migrates consumers and deletes the duplicates. Wave 3 (Mark, 2026-10-10: "urgently pursue all simplifications") turns the former LATER ideas into packages: SIM-shred, SIM-policy, SIM-cap, SIM-sim and SIM-repo-1/2. SIM-repo-1 and SIM-sim's harness need nothing and start with wave 0; the others start when their Needs merge. Each package is one session; tier A packages run on the strongest model.

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

**Change to SPEC.** (1) The journal is the only durable source of truth; every other store is a projection rebuilt from it, or a cache named in SPEC with the journal offset it reflects. (2) Owner messages are intents: `owner.inform` with a subject and the subject's revision, rendered at dispatch, so OP-3 drops a message whose subject has moved on. (3) One outcome record per goal, revisable, latest revision wins (OP-7). (4) A learning mechanism is off until it beats the baseline on SPEC §1's objective on independent goals (LOOP-3). (5) FORGET erases in the journal and rebuilds projections (CAP-3). (6) Pull-first (Mark, 2026-10-10): STATUS is the owner's primary view; only urgent classes are pushed; the daily digest is removed from CH-15. (7) A subject's payloads may be sealed under a per-subject key; deleting the key is erasure (CAP-3), and it reaches backups.

**Acceptance.** Mark approves the diff. doclint and trace pass. **Usage estimate.** Small, under 40k tokens. Tier B.

## SIM-check: one journal invariant checker (tier A)

**Goal.** Floor invariants are written today as many separate crash-cut and composition tests, and fuzz "Cleared" trusts the target's own PASS lines.

**Change.** A package of predicates over any journal: no effect dispatched without a grant valid at dispatch (OP-3); every dispatched effect ends settled or explicitly uncertain (OP-4); no erased subject readable from any projection (CAP-3); no owner message dispatched with a stale subject revision (added by SIM-owner-hold). The same checker runs in property tests over generated logs, in CI over the five-journey runs, and at runtime as a STATUS line when it finds a violation.

**Requirement IDs.** OP-3, OP-4, OP-5, CAP-3. **Acceptance.** Each predicate has a generated counterexample journal it rejects and a valid one it accepts; mutants that drop each predicate fail. **Usage estimate.** Medium, under 120k tokens. Tier A.

## SIM-proj: journal snapshots and a projection API (tier A)

**Change.** `Projection` interface: `Apply(record)`, `Snapshot() / Restore(bytes, offset)`. The journal writes periodic snapshots with the offset they reflect; boot restores the latest snapshot and replays the tail. Projections never persist as a source of truth.

**Requirement IDs.** OP-4, RES-4. **Acceptance.** Rebuild from snapshot plus tail equals rebuild from empty, for a generated log (property test); a corrupt snapshot falls back to full replay. **Usage estimate.** Medium, under 120k tokens. Tier A.

## SIM-owner-hold: owner texts are intents; the pacer hold becomes a projection (tier A)

**Needs.** SIM-sd, SIM-proj, DEL-1 and PACE-1 merged (#709, #708: the two point fixes this generalizes).

**Change.** Owner texts are `owner.inform` intents with a subject and subject revision, rendered at dispatch. The pacer's hold and owner-state held texts become a projection over those intents. Quiet hours, urgent classes, eviction priority and held-text visibility become rules in that projection: provider security alerts sent at once (W5-Dc-r13), class-aware eviction (r15), the held marker on packed released texts (r16), and forget dropping a held text (r17). The pacer's string hold and its own persistence are deleted.

**Requirement IDs.** OP-3, OP-4, OP-9, CH-15, CAP-3. **Acceptance.** A guest reply accepted before a crash is delivered after restart (DEL-1's test, unchanged); a "Cleared" whose subject revised before dispatch is not sent; a forgotten subject's held text is not sent (r17); a flood of agent texts does not evict a held approval (r15); a security alert bypasses quiet hours (r13); a released text packed after a hold carries its held marker (r16); SIM-cases' hold cases pass. Net lines go down. **Usage estimate.** Under 130k tokens. Tier A.

## SIM-pull: STATUS is the owner's view; only urgent texts are pushed (tier A)

**Needs.** SIM-owner-hold; SIM-sd carrying the pull-first rule (Mark chose pull-first, Decisions card 2026-10-10).

**Change.** STATUS becomes one projection of the owner's open questions, results and alerts at their latest revision, always current. Push is kept only for urgent classes: approvals that block work, security alerts, STOP/RESUME confirmations, and the classes SPEC names as urgent. Everything else is no longer pushed; it appears in STATUS. The daily digest is deleted rather than rebuilt: `broker/digestqueue` in whole (durability, leases, receipts, `Sender`, `Batch`, `Snapshot`), the agentosd digest box, and the digest gate (`batchLeaks`, the "`Send` only in `sendReady`" rule). The pacer keeps only what urgent push needs.

**Requirement IDs.** OP-3, OP-4, OP-9, CH-2, CH-15, CAP-3 (as amended by SIM-sd). **Acceptance.** STATUS after a crash shows the same open items as before it; a resolved question leaves STATUS on its next read; a forgotten subject never appears in STATUS; an urgent text is pushed within quiet hours and a non-urgent one is not; exactly one dispatch path sends owner texts, checked by a call-site test (r21's case); no owner content reaches a log sink, checked with a synthetic canary (r22's case); no queue of unsent texts can fill during a carrier outage, because none is kept (r18's case); SIM-cases' digest cases are either met or listed as retired with the digest. Net lines go down. **Usage estimate.** Under 130k tokens. Tier A.

## SIM-cases: W5-D cases become tests against main (tier A)

**Goal.** Mark chose (decision 1, 2026-10-10) to stop W5 building and keep the W5-D draft PRs open as reference, with their crash, acknowledgement and forget cases extracted as tests. This package owns that extraction so no case is lost when the drafts' mechanisms are not built.

**Change.** Read each open W5-D draft PR and list every crash cut, acknowledgement and forget case it tests in `briefs/SIM-cases.md` (one line each: draft PR, case, the outcome the owner sees). Write each case as a test against main's observable behaviour (owner text sent or not, after restart or forget), not against the draft's internal types. Cases main already passes land as tests in this PR. Cases main fails are not skipped or quarantined: each is assigned in the list to SIM-owner-hold, SIM-pull or SIM-erase, or listed as retired with the digest, whose acceptance then includes it.

**Requirement IDs.** OP-4, CAP-3, CH-15. **Acceptance.** Every open W5-D draft PR appears in the list with its cases or "no owner-visible case"; each case is a passing test here or assigned to a named SIM package. **Usage estimate.** Under 120k tokens; split by draft range if the list exceeds 20k tokens. Tier A (agentosd tests).

## SIM-outcome: one revisable outcome record (tier A)

**Change.** `outcome{goal_id, intent_id, verdict, source, revision}` in the journal; the suite, adoption gate, attention and digest read the latest revision. Delete `change.Outcome`, `loops.Outcome`/`Action` and `grants.OwnerVerdict` in favour of it; remove both first-write-wins paths (`grants/gate.go` "keeps only the first verdict", `loops/harvest.go` "the suite keeps the first"). Evidence counts distinct `goal_id`, not effects.

**Requirement IDs.** OP-7, CHG-1, LOOP-3. **Acceptance.** A verdict revised to wrong after adoption reverts the adoption decision; eight effects from one goal count as one episode. **Usage estimate.** Large, under 150k tokens. Tier A.

## SIM-erase: forget once, in the journal (tier A)

**Needs.** SIM-sd, SIM-proj, SIM-check.

**Change.** FORGET erases the subject in the journal (`journal/erase.go`) and rebuilds affected projections; SIM-check's "no erased subject readable" predicate is the test. The per-package forget hooks are deleted as each store becomes a projection. Out of scope: restores, which the forget log over backups governs (W3-forget-b1-5, b1-6, with W3-forget-b2c-f1-r2 and r4), and recall's take-back (`broker/recall`, `recalltool`), which is not a projection and keeps its rows W3-forget-reach-r1 to r5.

**Requirement IDs.** CAP-3. **Acceptance.** The checker finds no erased subject in any projection after forget and after restart; a source re-offering a forgotten reference in a higher generation is never sent (W5-Dc-r5); SIM-cases' forget cases pass. **Usage estimate.** Medium, under 120k tokens. Tier A.

## SIM-core: the trusted core is a named list (tier A)

**Change.** One file lists the core packages (journal, grants, vault, sockets, egress, childproc, verb, guest, meter, guesterr). A CI import check fails when a package outside it imports a core write path other than the journal's `Submit`. `tools/risk_tier.py` reads the list: core = A.

**Requirement IDs.** ARC-1. **Acceptance.** A fixture package that writes grants directly fails the check; `risk_tier.py` rates a core file A and a non-core broker file B. **Usage estimate.** Small, under 60k tokens. Tier A: it changes `tools/risk_tier.py` and `.github/`, both tier A paths.

## SIM-shred: forget by deleting a per-subject key (tier A)

**Needs.** SIM-erase, SIM-proj; SIM-sd item 7.

**Goal.** SIM-erase makes forget happen once in the journal, but backups and snapshots still hold copies, which is why the restore-path rows (W3-forget-b1-5, b1-6, W3-forget-b2c-f1-r2, r4) exist.

**Change.** Each subject's payloads in the journal and snapshots are sealed under a per-subject data key held in the vault process. FORGET deletes the key (and its vault backup copy), so every copy becomes unreadable, backups included. Indexes keep only keyed hashes, never plaintext. Journal records whose key is gone read as `erased`. The forget log over backups is then reduced to "key deleted" records, and the restore-path rows are rechecked and dropped if the acceptance below covers them.

**Requirement IDs.** CAP-3, ARC-1, OP-4. **Acceptance.** A synthetic canary written for a subject is unreadable in the journal, a snapshot and a restored backup after forget; replay after forget succeeds, with the subject's records as `erased`; losing the vault key store fails closed (no plaintext fallback). **Usage estimate.** Under 140k tokens; if the vault change alone exceeds half, split it off as SIM-shred-vault. Tier A.

## SIM-policy: policy as data, one evaluator (tier A)

**Needs.** SIM-outcome, SIM-pull, SIM-core.

**Change.** Urgent classes, quiet hours, pacing allowances, adoption rules (what counts as a gain, whether a tie adopts) and retry policies become declarative records evaluated by one small deterministic evaluator inside the core. The evaluator only matches fields and compares thresholds: no loops, no user-defined functions, no I/O. A policy change is itself a journaled intent, needing owner approval and revertible. The constants these replace (for example in `loops/loop1.go`, `owner/pacer.go`, `grants`) are deleted.

**Requirement IDs.** OP-5, CHG-1, CH-15, LOOP-3. **Acceptance.** Each replaced constant has a test showing identical decisions from the default policy record; a policy change without approval is refused; reverting a policy intent restores earlier decisions; the evaluator's grammar test rejects any construct beyond match and compare. **Usage estimate.** Under 140k tokens. Tier A.

## SIM-cap: capability grants scoped per intent (tier A)

**Needs.** SIM-core, SIM-check, SIM-policy.

**Change.** A grant names the intent (action, subject, bounds, expiry) it authorizes, instead of standing authority per account or tool. The broker mints the capability at authorize and checks it at dispatch (OP-3). A capability cannot be widened by its holder, and it is spent or expires with its intent. Standing per-account grants become policies (SIM-policy) that mint capabilities, or are deleted where nothing uses them.

**Requirement IDs.** OP-3, ARC-1, Invariant C. **Acceptance.** An effect dispatched with a capability for a different intent, a widened bound, or after expiry is refused; replay rebuilds outstanding capabilities exactly; SIM-check gains the predicate "every dispatch carries a capability minted for that intent". **Usage estimate.** Under 140k tokens; if the grants rewrite exceeds that, split it into mint-and-check, then remove the standing grants. Tier A.

## SIM-sim: deterministic simulation of the broker (tier A)

**Needs.** SIM-check for the second half; the harness can start at once.

**Change.** A seeded scheduler with a fake clock, fake filesystem (crash cuts at every write and fsync) and fake transports drives the real broker state machine. A failing seed replays exactly. Every run is judged by SIM-check. The scattered crash-cut and composition tests that a seed sweep then covers are deleted, each named in the PR.

**Requirement IDs.** OP-3, OP-4, OP-5, CAP-3. **Acceptance.** The same seed gives a byte-identical journal twice; a known bug re-introduced as a mutant (DEL-1's lost reply, the stale "Cleared") is found within a fixed seed budget; CI runs a bounded seed sweep. **Usage estimate.** Under 140k tokens. Tier A.

## SIM-repo-1: work items as GitHub issues, BOARD generated (tier A)

**Change.** Define the work-item schema as issue labels (ID, state, gate, class, tier, lane) with the brief as the issue body or a link to it. Write `tools/board.py` to generate BOARD.md from issues and PRs, and a one-time migration script that creates one issue per non-terminal BOARD row (dry-run by default). CI checks that the generated BOARD matches the committed one. This package does not run the migration.

**Requirement IDs.** None in SPEC (process; CLAUDE.md, OPERATING). **Acceptance.** The dry run over today's BOARD.md round-trips: the generated BOARD from the planned issues equals the source for every non-terminal row; the label schema covers every state doclint accepts. **Usage estimate.** Under 100k tokens. Tier A (`tools/`, `.github/`).

## SIM-repo-2: migrate, generate METRICS and TRACE, retire doclint's board rules (tier A)

**Needs.** SIM-repo-1.

**Change.** Run the migration. Merged and dropped rows stay in an archived BOARD history file; everything live is an issue. METRICS and TRACE are generated by the `trace` workflow from PRs and tests, as TRACE already is. LATER becomes a label. MARK-QUEUE is replaced by the Decisions cards and a `decision` label. doclint's BOARD and LATER rules are deleted. `board.py render --repo` reads work items only from issues opened by a repository collaborator, so an outsider's issue with the `work-item` label cannot place a row (release finding from the #721 L3; failure path: anyone who can open an issue adds a fake row). CLAUDE.md and OPERATING are amended to match (a change to the operating contract: the PR names the lines and needs Mark's approval, as SPEC changes do).

**Requirement IDs.** None in SPEC. **Acceptance.** Every live BOARD row has exactly one issue; the generated BOARD equals the pre-migration live rows; no hand-maintained status file remains other than briefs, decisions and reviews. **Usage estimate.** Under 100k tokens. Tier A.
