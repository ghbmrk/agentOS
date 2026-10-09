# SR3-mail-w: wire unattended mail organize in agentosd

**Source.** BOARD row SR3-mail-w is the release placeholder that L3 on #571 (point 6) filed. Security on #579 added to it in two rounds:
- R2: the `InUse` hook calls `Engine.InUse` with this adapter's account; `mail.Config.Now` and `journal.WithClock` use one clock; a wiring test pins both.
- R1, re-signed on R3: the S-R1 expiry deferral and the delete/report-spam pin rested on mail not yet running unattended. SR3-5-f2 (#616, d43fba8) has now merged. It pins delete-remote intents and never expires the judgement of an intent in use (M18), so the deferral is safe to end here.

Anchors: ADP-2 (organize: bounded, visible, undoable), CRED-1 and CRED-7 (custody), OP-3 (recheck before dispatch), CH-11 and CH-16 (UNDO), REV-2. Records: `broker/mail/ASSUMPTIONS.md` M1, M9, M16, M18.

**This package is split into two rows.** One package cannot hold the work in under 150k tokens. Nothing on main serves a mailbox to agentosd, and the wiring needs that before it can build anything:
- **SR3-mail-w1:** the vault holds the mail account and serves `mail.Store` over a socket.
- **SR3-mail-w2:** agentosd wires the adapter, the hook, the shared clock, the recheck and the digest UNDO.

w2 needs w1. Each row has its own Delivery section below.

## What happens on main (d43fba8)

- **No process serves a mailbox.**
  - `mail.Store` has nine methods (`broker/mail/mail.go:110-126`).
  - `mail/imapsmtp` implements it (`imapsmtp.go:66`, `New` at 74), and no package under `broker/cmd` imports it.
  - M1 says `imapsmtp` "is to be linked only into the vault process (`agentos-egress`), which serves `Store` to `agentosd` over a socket", and "Wiring must not link `imapsmtp` into `agentosd`".
  - The precedent for an account the vault holds and serves on a uid-restricted socket is `broker/cmd/agentos-egress/smsaccount.go`. Its listener is `listen(dir, name, uid)` (`server.go:731`).
- **agentosd builds no mail adapter.**
  - `evidence.go:127-131` says "agentosd does not link the adapter" and copies `opDeliver` and `mailExecutor` as string constants.
  - `main.go:655-658` says "No mail account is connected in this process yet". `e.mail` stays nil.
  - L3 on #579, point 5, says the same.
- **No organize executor and no Escalator are registered.**
  - The gate's dispatch recheck runs `Verifiers[in.Account].(Escalator)` (`broker/grants/gate.go:736`) after looking up `Declared[spec.Executor]` (line 726).
  - `mail.Adapter.Escalate` exists (`broker/mail/guard.go:436`), and it is where the pins (M16) and the expiry (`expire`, `guard.go:639`, M18) run.
  - Today no mail adapter is in `daemon.Config.Executors` (`broker/daemon/daemon.go:120-122`, checked at 278-288), in `Grants.Declared` or in `Grants.Verifiers`. So there is nothing for OP-3 to recheck.
- **The journal and the adapter keep separate clocks.**
  - `daemon.Run` calls `journal.Open(store, gate, execs, red)` with no options (`daemon.go:309`), so the engine stamps records with its default clock (`journal/engine.go:49-59`; `WithClock` is at 52).
  - `mail.New` defaults `Config.Now` to `time.Now` (`mail.go:198`, default at 269). The two clocks are wired nowhere.
  - The adapter's bound counts Succeeded places since `Now()-24h`, through `InUse(action, since)` (`mail.go:174-182`), and compares that with times the engine stamped. So if the journal clock lags the adapter's, Succeeded places age out early and the bound under-counts (Security R2).
- **`InUse` has no caller.**
  - `Engine.InUse(account, action, since)` (`engine.go:646`) is the hook M18 names. Nothing passes it to `mail.Config.InUse`.
  - A nil hook means every organize is asked (`askEach`), no pin expires, and pins grow without bound (M18).
- **The digest has no mail line, and UNDO cannot reach mail.**
  - `mail.Summarize` (`undo.go:120`) and `Digest.Line(undoID, until)` (`undo.go:151`) build the ADP-2 digest line. `Adapter.Undo` (`undo.go:53`) restores only what is unchanged (M9). `UndoWindow` is 7 days (`undo.go:14`).
  - agentosd's digest (`broker/cmd/agentosd/digest.go`, `digestConfig` at 84) has no mail source.
  - The owner channel parses `UNDO <id>` (`broker/owner/parse.go:48`) and sends every id to auto-reply undo (`channel.go:436` → `autoreply.go:208` `undoLocked`). That answers "Nothing to undo for <id>." to any id it did not queue.

## Decision

Agentosd runs the mail adapter in-process over a `mail.Store` client that talks to the vault's socket. One late-bound value carries the engine into the hook, and one clock function, owned by `daemon.Config`, is handed to both `journal.WithClock` and `mail.Config.Now`. A digest UNDO is resolved from the journal's own trail, so it needs no new store.

Rejected alternatives:
- **Link `imapsmtp` into agentosd.** This puts the mailbox credential in the control process, against CRED-1 and M1, which is exactly what the custody split exists to prevent.
- **Run the adapter inside egress.** The executor, verifier and pins would then sit in the vault process. That process would need the journal and the gate, which collapses the split the other way.
- **Leave `InUse` nil until later.** This is unsafe once mail runs unattended: every organize is asked, no pin expires, and pins grow without bound (M18).
- **Bind `InUse` to `AuthorizedSince` (`engine.go:605`).** That counts authorized intents, not places held under the bound: it misses in-flight and outcome-unknown intents and Succeeded places, which M18 needs.
- **A separate clock option in each package, set from the same source.** Two settings can drift apart with no test to see it. One field, one function value, and a wiring test that compares stamps closes that.
- **Persist digest UNDO ids in a new file.** The journal already holds every organize intent's evidence (`mail.Change` through `ParseChange`, `undo.go:17`), and `Engine.Trail()` (`engine.go:671`) returns it. The ids are derived instead: account plus digest day, read back from the trail. That way the undo survives a restart, and there is nothing new to keep consistent.

---

## SR3-mail-w1: the vault serves the mailbox

### Requirements (local IDs)

- **W1-a (served Store; CRED-1, CRED-7, M1).**
  - agentos-egress holds one mail account: the address, the server and the credential reference.
  - It builds `imapsmtp.Store`, with the credential through `imapsmtp`'s callback on each connection, and serves the nine `mail.Store` methods on a socket. The socket comes from `listen` with agentosd's uid, as the SMS socket does.
  - No reply on the socket carries the credential or the server's login words (M1 already requires this of `imapsmtp`).
- **W1-b (client).**
  - A package agentosd can import provides a client that implements `mail.Store` over that socket. Errors map onto the same sentinels `mailtest` returns, so the adapter's validity checks (M15) behave as they do in tests.
  - Reuse the SMS socket's framing; a new codec needs the one-line reason CLAUDE.md asks for.
- **W1-c (custody pin).** A test fails if any package agentosd links imports `broker/mail/imapsmtp`. Extend the existing ARC-2/custody import test (M1's note asks for exactly this). `TestAdapterHoldsNoCredential` keeps passing.
- **W1-d (setup).** The account is set up the way `smsaccount.go` sets up the SMS account: through the local UI, never through an owner text. It is absent by default. While absent, the socket answers every call with a not-connected error, and agentosd treats that as "no mail account" (as on main today).

### Failing-test-first

Use synthetic canaries only. The credential in every test is a canary string that the test then searches for in all socket traffic and logs.

| ID | Test | Why it fails on main |
|---|---|---|
| W1-a | Run an egress test server over `mailtest`'s IMAP double. The client calls each of the nine methods and gets the same results as calling `mailtest` directly; the canary appears in no frame. | There is no socket and no handler. |
| W1-b | The adapter suite's `Ref`/validity case (M15), run through the client: a stale validity is refused. | There is no client. |
| W1-c | The import test lists agentosd's transitive imports and fails on `imapsmtp`. Mutant: import it from a test-only agentosd file, and the test fails. | The test does not check `imapsmtp`. |
| W1-d | With no account set up, every method returns the not-connected error, and agentosd starts. | No handler exists. |

**Controls that must keep passing:** all of `broker/mail/...`, `broker/cmd/agentos-egress`, and `TestAdapterHoldsNoCredential`.

**Threat check:**
- Can any agentosd code path, including tests linked into its binary, reach `imapsmtp`?
- Can a peer other than agentosd's uid connect to the socket?
- Does any error string from the server (the server's own words after a login error) cross the socket?
- Can `Submit` over the socket send from an address other than the account's own address?

**Scope:**
- `broker/cmd/agentos-egress/` (a new `mailaccount.go`, its test, and the listener line in `server.go`).
- A new client package `broker/mail/mailsock/` with its tests.
- The custody import test, wherever it lives today (the builder names it in the PR).
- `broker/mail/ASSUMPTIONS.md` M1 (record that the wiring now exists).
- `broker/cmd/agentos-egress/ASSUMPTIONS.md`.
- BOARD row SR3-mail-w1.

**Order:** none of #614, #617, #620, #622, #626, #628, #629 or #621 edits `agentos-egress` or `broker/mail`. w1 can start now.

### Delivery (w1)

- **Builder model:** the strongest model. Risk tier **A** (`egress`, credentials).
- **Review:** L3 on the strongest model with the threat check above, plus a separate Security section (OPERATING §3–4).
- **Estimate and checkpoint:** about 90k tokens. This is a checkpoint, not a ceiling (OPERATING §5).
- **Split rule:** if W1-d is still red at the checkpoint, ship W1-a to W1-c with the account set from a file the vault owns, and move the UI setup to its own row.

---

## SR3-mail-w2: agentosd wires unattended organize

### Requirements (local IDs)

- **W2-a (adapter and recheck; ADP-2, OP-3).**
  - When the w1 socket reports an account, agentosd builds `mail.New` over the w1 client.
  - It registers the adapter as executor `mail.Tool` in `daemon.Config.Executors`, with `mail.Declared()` (`declare.go:120`) under `Grants.Declared[mail.Tool]` and the adapter as `Grants.Verifiers[cfg.Account]`.
  - So `Escalate` runs at authorize and again at every dispatch recheck (`gate.go:736`).
  - `evidence.go` drops its copied constants and uses `mail.OpDeliver` and `mail.Tool`, and `e.mail` is the adapter.
- **W2-b (the hook; M18, Security R2).**
  - `mail.Config.InUse` is `func(action string, since time.Time) []journal.Use { return eng.InUse(cfg.Account, action, since) }`.
  - `eng` is bound after `journal.Open` returns, through a late binding like `recalltool.LateExecutor` (`main.go:603`).
  - Before the binding is set, the hook answers "unknown", never "nothing in use". Choose whichever of these M18 already defines as fail-closed: return the pins as in use, or make `Escalate` ask.
  - The account is the adapter's own `cfg.Account`, never a parameter the caller passes.
- **W2-c (one clock; Security R2).**
  - `daemon.Config` gains `Now func() time.Time`, defaulting to `time.Now`.
  - `daemon.Run` passes `journal.WithClock(cfg.Now)` to `journal.Open` (`daemon.go:309`).
  - agentosd sets `mail.Config.Now` to the same function value.
- **W2-d (digest line and UNDO; ADP-2, CH-11, CH-16, M9).**
  - The digest gains a mail source. It reads the day's Succeeded organize intents for the account from `Engine.Trail()`, parses each one's evidence with `ParseChange`, and adds `Summarize(...).Line(id, day+UndoWindow)`.
  - `id` is derived from the account and the day, and the derivation is unchanged across restarts.
  - `UNDO <id>` reaches `Adapter.Undo` with exactly those changes. The routing uses an owner-channel hook consulted after auto-reply undo finds no queued id, so no auto-reply behaviour changes.
  - Past the window, the reply says the undo has expired. The `UndoReport.Text()` sentence (`undo.go:35`) is the reply.
- **W2-e (record).**
  - agentosd's `ASSUMPTIONS.md` records the hook, the clock and the UNDO derivation.
  - `broker/mail/ASSUMPTIONS.md` M18 notes that the hook is wired.
  - The S-R1 expiry deferral line, wherever SR3-5-f2 recorded it, is closed with this PR's number.

### Failing-test-first

Use the `mailtest` double behind the w1 client in a test server, and synthetic addresses only.

| ID | Test | Why it fails on main |
|---|---|---|
| W2-a | Start agentosd's wiring with a test account and submit an organize intent. Authorize calls `Escalate` once. Between authorize and dispatch, move the message in the double: the recheck refuses the dispatch (OP-3). | No executor or Verifier is registered. |
| W2-b account | Two accounts, A and B, with B holding 200 Succeeded organize places today. A's adapter is not bounded by B's places. A mutant that passes `""` or B's account fails. | No hook is wired. |
| W2-b bound | The hook is non-nil after wiring. A 25-hour-old pin of an authorized intent survives expiry, and one with no live intent expires. Mutant: a nil hook; the test fails. | The hook is nil, and nothing expires. |
| W2-b early | `Escalate` before the engine is bound does not report an empty in-use set. | No hook is wired. |
| W2-c | One fake clock drives the daemon. An organize Succeeds at T. At T+23h59m, the bound still counts it. The record's journal stamp equals the adapter's `Now()` at execute. Mutant: drop `WithClock`; the stamps differ and the count falls short. | The engine uses its own clock. |
| W2-d | Three organize effects on day D give a digest line with `UNDO <id>`. `UNDO <id>` restores the unchanged ones and reports the changed one as skipped. After a restart, the same id still works. At D+7d+1m, the reply says it has expired. | There is no mail digest line, and UNDO answers "Nothing to undo". |
| W2-d control | An auto-reply `UNDO <id>` behaves exactly as on main. | Passes on main; quote it. |

**Controls that must keep passing:**
- all of `broker/mail`, especially the SR3-5-f1 and SR3-5-f2 pin and expiry tests;
- `broker/grants`, `broker/journal`, `broker/daemon` and `broker/owner`;
- agentosd's evidence tests (the CH-20 delivery with no account still falls back to text);
- the digest capacity tests.

**Threat check:**
- **Per-account scope.** Can the hook ever count, or spare, another account's places? Can a second adapter share the first one's binding?
- **Fail-closed before binding.** Between `mail.New` and the binding, can `Escalate` run and expire a live intent's judgement?
- **Clock.** Is there any path where the engine and the adapter read different clocks (a restart, a test helper, a `Reconcile` path)?
- **Recheck.** Does every organize intent reach the Escalator at dispatch, including one replayed after a restart (M16: no judgement means `NotApplied`)?
- **UNDO.**
  - Can a forged or guessed id undo another account's or another day's changes?
  - Can an UNDO restore an item the owner has since changed (M9)?
  - Does an UNDO go through a journaled intent, or does it act outside the journal? REV-2 does not require it, because organize is reversible, but the reviewer states which path it takes and why.
- **ARC-2.** No inference is on the path.

**Out of scope:**
- Mail as the CH-20 evidence destination beyond setting `e.mail` (CH-20w).
- The box's own mailbox (ADP-13).
- Watcher-driven proposals: who proposes an organize intent does not change here.
- The `Pending`-ask residuals SR3-5-f2 recorded in LATER (`SR3-5-f2 l2`–`l6`).
- Any change to `broker/mail` beyond the ASSUMPTIONS line.

**Scope:**
- `broker/daemon/daemon.go` (`Config.Now` and the `Open` call only) and a daemon test.
- `broker/cmd/agentosd/`: a new `mail.go` and `mail_test.go`, plus `main.go`, `evidence.go` and `digest.go`, each limited to the wiring and the mail source.
- `broker/owner/channel.go`: one hook field and its call, after `undoLocked` misses, plus an owner test.
- `broker/cmd/agentosd/ASSUMPTIONS.md` and `broker/mail/ASSUMPTIONS.md` M18.
- BOARD row SR3-mail-w2.

**Needs:** SR3-mail-w1, SR3-2-f1, SR3-5-f1, and SR3-5-f2 (merged, #616 d43fba8).

**Order against open PRs: build after #622 and #628 merge.**
- **#622 (W5-Dc-r12).** It edits agentosd `digest.go`, `forget.go`, `main.go` and `ASSUMPTIONS.md`. Start w2 from a main that includes it.
- **#628.** It edits agentosd `main.go`, `learn.go` and `ASSUMPTIONS.md`. Start after it too.
- **#626, #629 and #621.** These edit agentosd `ASSUMPTIONS.md` only; #629 and #621 also edit `broker/daemon/inference_test.go`, which this scope does not touch. If any is still open, merge main before review, and the ASSUMPTIONS edit goes last.
- **#617.** It edits agentosd `forget_agent_test.go` and `grants` tests. There is no overlap.
- **#619.** It edits `digest_capacity_test.go`, a control here. Merge main before review if it lands first.
- **#614 and #620.** These touch only records. There is no overlap.

### Delivery (w2)

- **Builder model:** the strongest model. Risk tier **A** (`daemon`, `broker/cmd/agentosd`, `broker/owner`).
- **Order of work:**
  - Write the tests first, after w1 merges and the PRs above merge.
  - Before opening the PR, run `python3 tools/risk_tier.py --git origin/main HEAD`.
- **Review:**
  - L3 on the strongest model with the threat check above.
  - A separate Security section that re-signs R1 and R2 from #579.
  - The UX and Potency lens on the digest line and the UNDO replies.
- **Estimate and checkpoint:** about 120k tokens. This is a checkpoint, not a ceiling (OPERATING §5).
- **Split rule:** if W2-d is still red at the checkpoint, ship W2-a to W2-c and W2-e alone. ADP-2 requires the UNDO, so organize grants stay refused for mail until it lands (the wiring ships, the organize verb is not offered). Move W2-d to a new row, SR3-mail-w3, and mark the row's dependents as waiting on it.

## Done (each row)

- CI is green.
- Each local ID is covered by a passing test or a record line.
- The mutant runs named in the tables are quoted.
- Risk tier A is noted in the PR.
- No credential or personal data appears in any file, fixture or log.
