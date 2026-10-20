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

**Order.** Wave 0 fixes foundation defects and needs no spec change. Wave 1: SIM-check, SIM-proj and SIM-cases need no spec change and can start at once; SIM-owner-hold, SIM-pull, SIM-outcome and SIM-erase need SIM-sd. Wave 2 migrates consumers and deletes the duplicates. Wave 3 (Mark, 2026-10-10: "urgently pursue all simplifications") turns the former LATER ideas into packages: SIM-shred, SIM-policy, SIM-cap, SIM-sim, SIM-split, SIM-outer and SIM-repo-1/2. SIM-repo-1 and SIM-sim's harness need nothing and start with wave 0; the others start when their Needs merge. Each package is one session; tier A packages run on the strongest model.

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

**Needs.** SIM-sd, SIM-proj, SIM-cases, DEL-1 and PACE-1 merged (#709, #708: the two point fixes this generalizes).

**Change.** Owner texts are `owner.inform` intents with a subject and subject revision, rendered at dispatch. The pacer's hold and owner-state held texts become a projection over those intents. Quiet hours, urgent classes, eviction priority and held-text visibility become rules in that projection: provider security alerts sent at once (W5-Dc-r13), class-aware eviction (r15), the held marker on packed released texts (r16), and forget dropping a held text (r17). The pacer's string hold and its own persistence are deleted.

**Requirement IDs.** OP-3, OP-4, OP-9, CH-15, CAP-3. **Acceptance.** A guest reply accepted before a crash is delivered after restart (DEL-1's test, unchanged); a "Cleared" whose subject revised before dispatch is not sent; a forgotten subject's held text is not sent (r17); a flood of agent texts does not evict a held approval (r15); a security alert bypasses quiet hours (r13); a released text packed after a hold carries its held marker (r16); a crash or failed save after a send never refills the hourly allowance; SIM-cases' hold cases pass. Net lines go down. **Usage estimate.** Under 130k tokens. Tier A.

## SIM-pull: STATUS is the owner's view; only urgent texts are pushed (tier A)

**Needs.** SIM-owner-hold, SIM-cases; SIM-sd carrying the pull-first rule (Mark chose pull-first, Decisions card 2026-10-10).

**Change.** STATUS becomes one projection of the owner's open questions, results and alerts at their latest revision, always current. Push is kept only for urgent classes: approvals that block work, security alerts, STOP/RESUME confirmations, and the classes SPEC names as urgent. Everything else is no longer pushed; it appears in STATUS. The daily digest is deleted rather than rebuilt: `broker/digestqueue` in whole (durability, leases, receipts, `Sender`, `Batch`, `Snapshot`), the agentosd digest box, and the digest gate (`batchLeaks`, the "`Send` only in `sendReady`" rule). The pacer keeps only what urgent push needs.

**Requirement IDs.** OP-3, OP-4, OP-9, CH-2, CH-15, CAP-3 (as amended by SIM-sd). **Acceptance.** STATUS after a crash shows the same open items as before it; a resolved question leaves STATUS on its next read; a forgotten subject never appears in STATUS; an urgent text is pushed within quiet hours and a non-urgent one is not; exactly one dispatch path sends owner texts, checked by a call-site test (r21's case); no owner content reaches a log sink, checked with a synthetic canary (r22's case); no queue of unsent texts can fill during a carrier outage, because none is kept (r18's case); SIM-cases' digest cases are either met or listed as retired with the digest. Net lines go down. **Usage estimate.** Under 130k tokens. Tier A.

## SIM-cases: W5-D cases become tests against main (tier A)

**Goal.** Mark chose (decision 1, 2026-10-10) to stop W5 building and keep the W5-D draft PRs open as reference, with their crash, acknowledgement and forget cases extracted as tests. This package owns that extraction so no case is lost when the drafts' mechanisms are not built.

**Change.** Read each open W5-D draft PR and list every crash cut, acknowledgement and forget case it tests in `briefs/SIM-cases.md` (one line each: draft PR, case, the outcome the owner sees). Write each case as a test against main's observable behaviour (owner text sent or not, after restart or forget), not against the draft's internal types. Cases main already passes land as tests in this PR. Cases main fails are not skipped or quarantined: each is assigned in the list to SIM-owner-hold, SIM-pull or SIM-erase, or listed as retired with the digest, whose acceptance then includes it.

**Requirement IDs.** OP-4, CAP-3, CH-15. **Acceptance.** Every open W5-D draft PR appears in the list with its cases or "no owner-visible case"; each case is a passing test here, assigned to a named SIM package, or retired with the digest. **Usage estimate.** Under 120k tokens; split by draft range if the list exceeds 20k tokens. Tier A (agentosd tests).

## SIM-outcome: one revisable outcome record (tier A)

**Change.** `outcome{goal_id, intent_id, verdict, source, revision}` in the journal; the suite, adoption gate, attention and digest read the latest revision. Delete `change.Outcome`, `loops.Outcome`/`Action` and `grants.OwnerVerdict` in favour of it; remove both first-write-wins paths (`grants/gate.go` "keeps only the first verdict", `loops/harvest.go` "the suite keeps the first"). Evidence counts distinct `goal_id`, not effects.

**Requirement IDs.** OP-7, CHG-1, LOOP-3. **Acceptance.** A verdict revised to wrong after adoption reverts the adoption decision; eight effects from one goal count as one episode. **Usage estimate.** Large, under 150k tokens. Tier A.

## SIM-erase: forget once, in the journal (tier A)

**Needs.** SIM-sd, SIM-proj, SIM-check, SIM-cases.

**Change.** FORGET erases the subject in the journal (`journal/erase.go`) and rebuilds affected projections; SIM-check's "no erased subject readable" predicate is the test. The per-package forget hooks are deleted as each store becomes a projection. Out of scope: restores, which the forget log over backups governs (W3-forget-b1-5, b1-6, with W3-forget-b2c-f1-r2 and r4), and recall's take-back (`broker/recall`, `recalltool`), which is not a projection and keeps its rows W3-forget-reach-r1 to r5.

**Requirement IDs.** CAP-3. **Acceptance.** The checker finds no erased subject in any projection after forget and after restart; a source re-offering a forgotten reference in a higher generation is never sent (W5-Dc-r5); SIM-cases' forget cases pass. **Usage estimate.** Medium, under 120k tokens. Tier A.

## SIM-core: the trusted core is a named list (tier A)

**Change.** One file lists the core packages (journal, grants, vault, sockets, egress, childproc, verb, guest, meter, guesterr). A CI import check fails when a package outside it imports a core write path other than the journal's `Submit`. `tools/risk_tier.py` reads the list: core = A.

**Requirement IDs.** ARC-1. **Acceptance.** A fixture package that writes grants directly fails the check; `risk_tier.py` rates a core file A and a non-core broker file B. **Usage estimate.** Small, under 60k tokens. Tier A: it changes `tools/risk_tier.py` and `.github/`, both tier A paths.

## SIM-split: one key-holder process per account, and a separate checker (tier A)

**Needs.** SIM-core (its list names the holder, not all of egress); SIM-check (item 3 adds its predicate).

**Fact.** `agentos-egress` (about 12.4k lines in `broker/cmd/agentos-egress`) opens the whole vault and reads every secret: proxy injection and the CRED-7 redactor (`broker/egress/proxy.go:375`, `:308`), and in `broker/cmd/agentos-egress/` mail (`mailaccount.go:178`), SMS (`smsaccount.go:170`), SIP (`sipaccount.go:199-200`, the per-account SIP password) and TPM policy keys (`trusted.go:706`). Today egress redacts every vault value from every proxied response and the journaled path (`proxy.go:308`, `:313`, `:455`, `:470`), which CRED-7 requires. A bug anywhere in it reaches every account.

**Change.** (1) A small unlock step derives the vault key and hands each account's secret to that account's holder, a process under its own uid that has only that secret and speaks a closed request shape (ADP-10). Egress, mail, SMS and SIP keep their logic but hold no secrets; they hand the holder a request it checks, and the holder injects the login, opens the upstream TLS connection itself, swaps a token-refresh response back to placeholders (CRED-5, ADP-10), and redacts its own secret from the response (CRED-7), so no login passes through egress in either direction. Keys tied to no account stay with the unlock step, which holds only these: the TPM policy keys, the recall identity key (`custody.go:708`), the update anchor (`custody.go:788`) and the recovery factors (`broker/recovery/`); the CH-4 seed (`custody.go:549`, `:670`; pending seed `enroll.go:119`) goes to the checker. Each holder redacts only its own secret, which would narrow CRED-7 (a provider B key echoed in provider A's response would pass), so egress keeps a redactor that holds no plaintext: the unlock step gives it keyed hashes of a fixed-length window of each vault value (a value shorter than the window is hashed whole), and it redacts any matching span on every response and journaled path, so all values stay redacted on every path and CRED-7 is met as written. Holders and the checker are broker processes (ARC-1). This extends the CRED-4 / ADP-5 executor pattern to the vault. (2) The CH-4 code seed moves out of the broker into a separate checker process; before releasing a login for a high-risk act (CH-10) the holder consults the checker. No SPEC change and no owner-visible change; the vault still unlocks once at boot. (3) SIM-core's list gains the holder and the checker as core packages; SIM-check gains the predicate "no secret appears in any process except its account's holder".

**Known gap (state in the PR).** A generator code is bound to time, not content, so a compromised broker could reuse a fresh code within its window; paper-grid cells do not have this gap.

**Requirement IDs.** CRED-4, CRED-5, CRED-7, ADP-10, CH-4, CH-10, ARC-1. **Acceptance.** A synthetic canary secret is readable only in its account's holder (checked by process); a request the holder's shape rejects never gets a login; a canary login and a refreshed canary token never appear in egress memory or traffic; a high-risk act without a checker-verified code is refused; restart re-hands every secret and the mail, SMS, SIP and proxy paths still pass their tests; a canary secret of account B in account A's response and in a journaled record is redacted by egress, and egress memory holds only keyed hashes of it, never the value. **Usage estimate.** Under 140k tokens; split the checker off if the holder split alone exceeds half. Tier A.

## SIM-split-b: the CH-4 checker process (tier A)

**Needs.** SIM-split part 1 (#1053, the holders).

**Change.** A separate `agentos-checker` process holds the CH-4 seed and the spent-step state. Over a verify socket (broker side) it checks the owner's code once and records one-time approvals, each bound to the hash of one exact request (host, method, escaped path, body) and expiring after 15 minutes. Over a redeem socket (holder side) a holder spends that approval before it releases a login for an irreversible or secret-class verb (CH-10); without it the act is refused. Both binaries refuse to run under a uid they serve and set themselves non-dumpable. Fixes #1053's R3 (binary hardening) and R4 (query-string test).

**Known gap (state in the PR).** A generator code is bound to time, not content, so a compromised broker could reuse a fresh code within its window; paper-grid cells do not have this gap.

**Requirement IDs.** CH-4, CH-10, ARC-1, CRED-1, ADP-10. **Acceptance.** A high-risk act without a checker-verified code is refused; an approval covers one exact request once; a spent step survives restart; wrong codes pause the checker. Tier A.

## SIM-split-wire: production wiring for holders and the checker (tier A)

**Needs.** SIM-split-b.

**Change.** The unlock step's custody leaves egress: one Keeper per holder hands each account's secret to its holder, and egress runs with the hash Redaction and the Holders map and no vault (CRED-1). The CH-4 seed and the pending enrol seed move out of custody to the checker and are re-handed after re-enrol; the broker's code check goes to the checker's verify socket, and the unlock step's last-spent step and the checker's are one store. The broker computes each act over the exact bytes egress forwards, and `checker.Act` opens in `broker/core/core.txt` for it. Low-tier and pre-allowed irreversible acts get an explicit path that the journal records. Each holder gets `-public-fetch` from the owner's per-login choice to let public machines use provider-side fetch, and a test pins the flag off by default (#1061 P1: the default-on mutant survives; without the flag, public machines lose provider-side tools through holders).

**Requirement IDs.** CRED-1, CRED-4, CH-4, CH-10, ARC-1. **Acceptance.** On a booted box, egress memory holds no canary secret and no vault key; a secret-revealing act passes only with a checker-verified code-generator code over its exact bytes, and any other high-risk act only with an approval the checker recorded for those bytes (a broker taken over can record the latter, SW-6). **Failure path.** Egress keeps the vault open in production, so one egress bug still reaches every account. Tier A.

## SIM-split-msg: mail, SMS and SIP through holders (tier A)

**Needs.** SIM-split-wire.

**Change.** Mail (`mailaccount.go`), SMS (`smsaccount.go`) and SIP (`sipaccount.go`) stop reading secrets from the vault and hand their requests to the account's holder, which injects the login and opens the upstream connection.

**Requirement IDs.** CRED-1, ADP-10. **Acceptance.** A canary mail, SMS or SIP password never appears in egress memory or traffic; the existing mail, SMS and SIP tests pass. **Failure path.** The per-account SIP password stays in egress, so an egress bug leaks every SIP login. Tier A.

## SIM-split-refresh: refreshed tokens persist through the unlock step (tier A)

**Needs.** SIM-split-wire.

**Change.** When a holder swaps a token-refresh response back to placeholders, the new token goes to the unlock step, which writes it to the vault and re-hands it, so a restart does not fall back to the expired token.

**Requirement IDs.** CRED-5. **Acceptance.** After a refresh and a restart, the holder uses the refreshed canary token, and the token never passes through egress. **Failure path.** A refreshed token lives only in holder memory; after a restart the account fails login until the owner re-enters it. Tier A.

## SIM-split-check: the secret-isolation predicate (tier A)

**Needs.** SIM-split-wire, SIM-check.

**Change.** SIM-check gains the predicate "no secret appears in any process except its account's holder" and runs it in its test, CI and runtime forms.

**Requirement IDs.** CRED-1, ARC-1. **Acceptance.** A fixture that copies a canary secret into egress memory fails the predicate. **Failure path.** A later change re-opens the vault in egress and no test notices. Tier A.

## SIM-split-fix: #1053 review findings (tier A)

**Needs.** SIM-split-wire for item 1.

**Change.** (1) R1, H-4: egress holds the hash key next to the window hashes, so a short mail or SIP secret can be brute-forced from egress memory. Before production wiring, set an entropy floor per value class or record a DECISIONS row accepting the class. (2) R2, H-3: the holder re-applies the op's BodyRule (ADP-10) itself rather than trusting egress, without narrowing what public machines may send. R3 (binary hardening) and R4 (query-string test) are fixed in SIM-split-b. (3) #1057 S1: `checker.Act` names no account, and every holder uid shares one redeem socket, so the act binds the account (credential name) and a holder redeems only acts for its own account. (4) #1057 S2: a test that `checker.Redeemer` reports any status but 204 and 403 as an error, so the holder refuses.

**Requirement IDs.** CRED-1, CRED-7, ADP-10, CH-10. **Acceptance.** A short canary secret has no recoverable hash in egress, or a DECISIONS row names its class; a body carrying `mcp_servers` or `web_search_options` is refused by the holder even when egress forwards it; an approval for account A's act is refused by account B's holder for the same bytes; a redeem answered 500 sends nothing. **Failure path.** A compromised egress sends `mcp_servers` with a real login attached. Tier A.

## SIM-outer: outer limits held by the provider (L1 spec diff, Mark approves)

**Change to SPEC.** Extend CRED-5 item 3 (narrowest login for worker-held routes) to every broker-held account: (1) OAuth scopes limited to what the enabled loops use, asked on the same consent screen as today; a loop needing a new permission asks once, when the owner turns it on. (2) Provider or card spend limits and provider rate limits set at about 2x the box's own cap (OP-8) and above the broker's per-hour bounds, so the broker's caps trip first in normal use and a provider refusal is itself the alarm: the broker texts that a provider refused what its own cap allowed, and pauses. (3) A provider with no narrow scope or limit is stated once in STATUS.

**Limit.** Bounds the worst case at about 2x the cap, not a hard guarantee where a provider offers no limit or scope. Owner notices it only on a clearly malicious act, plus one setup step per provider.

**Requirement IDs.** CRED-5, OP-8. **Acceptance.** Mark approves the diff. doclint and trace pass. **Usage estimate.** Small, under 40k tokens. Tier B.

## SIM-shred: forget by deleting a per-subject key (tier A)

**Needs.** SIM-erase, SIM-proj; SIM-sd item 7.

**Goal.** SIM-erase makes forget happen once in the journal, but backups and snapshots still hold copies, which is why the restore-path rows (W3-forget-b1-5, b1-6, W3-forget-b2c-f1-r2, r4) exist.

**Change.** Each subject's payloads in the journal and snapshots are sealed under a per-subject data key held in the vault process. FORGET deletes the key (and its vault backup copy), so every copy becomes unreadable, backups included. Indexes keep only keyed hashes, never plaintext. Journal records whose key is gone read as `erased`. The forget log over backups is then reduced to "key deleted" records, and the restore-path rows are rechecked and dropped if the acceptance below covers them.

**Requirement IDs.** CAP-3, ARC-1, OP-4. **Acceptance.** A synthetic canary written for a subject is unreadable in the journal, a snapshot and a restored backup after forget; replay after forget succeeds, with the subject's records as `erased`; losing the vault key store fails closed (no plaintext fallback). **Usage estimate.** Under 140k tokens; if the vault change alone exceeds half, split it off as SIM-shred-vault. Tier A.

## SIM-policy: policy as data, one evaluator (tier A)

**Needs.** SIM-owner-hold, SIM-pull, SIM-outcome, SIM-core. It starts after all of them merge (waste review, 2026-10-12): they settle which policies survive, and a policy layer built earlier would encode constants that they delete.

**Step 1, typed settings in one place.** First move every constant listed below into one typed settings record, with one default, journaled changes and one test per constant. That record alone may be the whole package.

**Gate on the evaluator.** Build the match-and-compare evaluator below only if the PR shows both of these: (a) a demonstrated need that typed settings cannot meet, such as an owner-visible policy that settings cannot express; and (b) net code deletion, meaning the evaluator plus its records are smaller than the code they replace. If either is missing, the package ends at step 1, and the evaluator becomes a `later` line.

**Change (only past the gate).** Urgent classes, quiet hours, pacing allowances, adoption rules (what counts as a gain, whether a tie adopts) and retry policies become declarative records evaluated by one small deterministic evaluator inside the core. The evaluator only matches fields and compares thresholds: no loops, no user-defined functions, no I/O. A policy change is itself a journaled intent, needing owner approval and revertible. The constants these replace (for example in `loops/loop1.go`, `owner/pacer.go`, `grants`) are deleted.

**Requirement IDs.** OP-5, CHG-1, CH-15, LOOP-3. **Acceptance.** Each replaced constant has a test showing identical decisions from the default policy record; a policy change without approval is refused; reverting a policy intent restores earlier decisions; the evaluator's grammar test rejects any construct beyond match and compare. **Usage estimate.** Under 140k tokens. Tier A.

## SIM-cap: capability grants scoped per intent (tier A)

**Needs.** SIM-core, SIM-check, SIM-policy (step 1 is enough; SIM-cap does not need the evaluator).

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

**Split (2026-10-10).** The migration changes the live repository, so it runs only after Mark taps its card, and everything that assumes issues exist waits for it. SIM-repo-2 makes the migration safe and the generated board enforceable; SIM-repo-2b runs after the migration and does the cutover.

**SIM-repo-2 change.** `board.py render --repo` reads work items only from issues opened by a repository collaborator, so an outsider's issue with the `work-item` label cannot place a row (release finding from the #721 L3; failure path: anyone who can open an issue adds a fake row); the gate lands before any issue template that applies the label. A `board-row` block whose JSON is not an object is refused with the issue's number, not a crash. Once BOARD.md carries `board.GENERATED`, CI renders the board from the live issues (`board.py check --repo`, D21) on every PR that changes BOARD.md and fails on a difference, because `board.py check` alone passes any committed generated BOARD.md; `board.yml` renders BOARD.md from the issues and opens it as a bot PR, as `trace.yml` does for TRACE.md. `board_migrate.py --apply` waits out GitHub's rate limits (403 or 429 with `retry-after`, or `x-ratelimit-reset`), pauses a second between issues, and reads the issues back to check the acceptance below; its skip-existing rerun already covers a stop partway. **Notes.** The migration creates about 270 issues, which notifies Mark once per issue: tell Mark before running it, so the burst is expected. METRICS.md is already generated (`metrics.yml`) and TRACE.md too (`trace.yml`).

**SIM-repo-2b change (after the migration).** Add `board.GENERATED` to BOARD.md and move its merged and dropped rows to an archived BOARD history file; everything live is an issue. METRICS counts merges and escalations from PRs and issues rather than BOARD.md history. LATER becomes a label. MARK-QUEUE is replaced by the Decisions cards and a `decision` label. doclint's BOARD and LATER rules are deleted. CLAUDE.md and OPERATING are amended to match (a change to the operating contract: the PR names the lines and needs Mark's approval, as SPEC changes do). Delete `board_migrate.py`.

**Requirement IDs.** None in SPEC. **Acceptance.** Every live BOARD row has exactly one issue; the generated BOARD equals the pre-migration live rows (`board_migrate.py --apply` checks both on read-back); CI fails a PR whose BOARD.md differs from the live issues; no hand-maintained status file remains other than briefs, decisions and reviews (2b). **Usage estimate.** Under 100k tokens each. Tier A.
