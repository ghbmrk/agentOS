# MAIL-world: the live mail clerk's VRB-2 world

Work item #3422, filed from [briefs/MAIL-main.md](MAIL-main.md) (PR #3442). Tier A, release. Checked on main at 764887f with #3442's head 1308544. Three slices, one session each, in the order below. All three wait on MAIL-main-a (#3442).

**Why.** `run.MailConfig.World` has no production source. MAIL-main-a's main returns `inbox.World{}`, and with that world the clerk acts on nothing:
- `AuthServ` and `AlertSenders` are empty, so `guardOff` holds and the clerk trashes and unsubscribes nothing (`no-alert-guard`, `clerk/inbox/alert.go`).
- Even with the guard on, VRB-2 would pass no unsubscribe: with no key records it gives `dkim-none`, and with no history `no-history`.

`LastOpened` is already the clerk's own (`clerk/run/seen.go`), and `Today` comes from this process's clock (D-154 rule 5).

**Standing rules.**
- **Keeper.** D-154 (decisions/D-154.md) makes the mail clerk a keeper process. It takes nothing of the world from the main side: every input below is read by the clerk itself, from the mailbox, from its own DNS lookups, or from a table shipped in its binary. Rule 4 still holds, so no new link to main-side code.
- **Fail closed.** Every source fails closed. A source that cannot be read in full leaves its fields empty, and an empty field must make the clerk refuse, never pass:
  - Empty `AuthServ` or `AlertSenders` turns the guard off (`guardOff`), so nothing is trashed or unsubscribed.
  - Empty `History` stops VRB-2 at `no-history`, before the lookalike clause reads `Contacts` and `KnownSenders`. Slice b therefore blanks all three together on any failure.

**Acceptance tests:** per slice, under "Acceptance tests (a)", "(b1)" and "(b2)" below.

## Where each field comes from

| Field | Source | Slice |
|---|---|---|
| `DKIMKeys` | The clerk's own DNS TXT lookups of `<s>._domainkey.<d>.` for the signatures on the mails of each read, through the process's netguard resolver | a |
| `ProviderTable` | A table shipped in the binary (`go:embed`): the registrable domains of mail service providers whose unsubscribe hosts VRB-2 accepts | a |
| `AuthServ` | A shipped per-provider table, keyed by the account's API or IMAP host suffix (Gmail: `mx.google.com`). An unknown provider gets `""`, so the guard is off and that account is never tidied (fail closed) | a |
| `AlertSenders` | The provider's own security senders from the same table, plus the domains of the clerk's own `PlanSenders` read (the DKIM-authenticated senders of services the owner holds accounts with). The field is empty until that read has completed in this process | a |
| `History`, `KnownSenders`, `Contacts` | The mailbox: the earliest delivery per sender in the inbox, archive and all-mail folders; the set of those senders; and the recipients of the owner's sent mail. Kept in a sealed incremental record | b1 (IMAP op), b2 |
| `Today`, `LastOpened` | Unchanged: own clock, own sealed record | none |

Senders the owner marks as financial or identity have no owner surface on the new core. That part of SPEC's alert rule is out of scope here. The builder of slice a files it as a `class:later` issue tagged `recheck`; the second net, the wording patterns, still applies.

## MAIL-world-a: key records, shipped tables and alert senders

1. **The process's network policy.** MAIL-main-a's main leaves `MailConfig.Guard` nil, so `imapsmtp` and `gmailNet` fall back to `netguard.New(netguard.Config{})`. That policy learns no network, and "nothing learned means nothing resolves" (`netguard/resolver.go`), so on a real box no name resolves at all: not Gmail, not IMAP, not DKIM.
   - The main builds one policy the way `cmd/agentos-egress/netguard.go` `netGuard` does (`netguard.Sources`, `Refresh`, `WatchEventsEvery` with `netguard.WatchNetlink`, no pins, refusals logged by address and reason only) and passes it as `MailConfig.Guard`. Copy the function; do not import `cmd/agentos-egress`.
   - If MAIL-unit or another slice has already landed this when a starts, skip this item.
   - If the unit's sandbox cannot read the routes or open netlink, the first read logs and the poll retries, as in egress. Record that in ASSUMPTIONS.
2. **Key lookups per read.** Add `inbox.DKIMNames(raw []byte) []string`. It returns the lookup name `s + "._domainkey." + alabel(d)` of each `DKIM-Signature` that `sigTags` parses, in exactly the form `verifyOne` looks up. Both use this one function, so the two cannot drift.
   - `MailConfig` gains `DKIM func(ctx context.Context, names []string) map[string]string`.
   - `openMail` collects the names from the mails it read and calls `DKIM` once. Its per-read world closure then sets `DKIMKeys`, the way it already sets `LastOpened`, so every judgement in that read sees one fixed set of keys.
   - When `DKIM` is nil, the closure leaves `World`'s own `DKIMKeys` as they are. The existing `fixtureWorld` tests and A21's eval fakes pass keys that way.
3. **The lookup** (`clerk/inbox/dkimdns.go`, in a package that already carries a `parser` line). `LookupDKIM(ctx, r *net.Resolver, names)` runs through `Guard.Resolver()`, and each name is looked up rooted (a trailing dot) so the search list never applies.
   - **Bounds:**
     - at most 2 names per mail and 400 names per read; later names are skipped, so their signatures fail;
     - names of at most 253 bytes, made of valid labels only;
     - 5 s per lookup and 30 s per read;
     - at most 8 KiB of TXT per name.
   - **Which record counts.** A name's record is the TXT strings of one record, joined. The lookup keeps the `p=` value only when all of these hold:
     - exactly one TXT record at the name parses as DKIM (two or more is ambiguous, so the name is absent);
     - `v=`, if present, is `DKIM1` and comes first;
     - `k=`, if present, is `rsa`;
     - `h=`, if present, lists `sha256`;
     - `s=`, if present, lists `email` or `*`;
     - `t=` has no `y` (RFC 6376 §3.6.1: a test-mode key counts as unsigned);
     - `p=` is non-empty (an empty one is revoked) and base64.
   - Any lookup error leaves the name absent. A failed lookup is never retried within the read.
4. **The shipped tables** (`clerk/inbox/providers.go`, `go:embed providers.txt`). A line-based file with three kinds of line, each ending with a `-- <source>` comment that names the provider's documentation or a header sample:
   - `esp <domain>`: a provider-table domain;
   - `authserv <api-or-imap-host-suffix> <id>`;
   - `security <api-or-imap-host-suffix> <address-or-domain>`.

   The file is parsed at init, and a bad line panics at test time. The table holds Gmail plus any provider the builder can cite; an entry that cannot be cited is left out, which fails closed. Host suffixes match in A-label form on dot boundaries, so `evilgmail.com` does not match `gmail.com`. The eval's `mailhub.test` entries go in tests only, never in the shipped file.
5. **Assembly** (`clerk/run/world.go`). `MailHost` builds the world `NewMailHost` passes to `openMail` and `accountPlan`. Each call:
   - reads the account's current settings (`readMail(h.dir)`, cached per `h.changes`), never settings captured at start. A world built before setup, or for a replaced account, therefore cannot keep the old provider's `AuthServ` or security senders;
   - fills `Today` from its own clock, plus `ProviderTable`, `AuthServ` and `AlertSenders`;
   - when `MailConfig.World` is set (tests and the eval), is not built: the given world is used unchanged, so the existing tests keep their worlds. When it is nil, the host sets it to its own before any `boxFor` call (which refuses a nil world).
6. **Alert senders from the clerk's own read.** The world's `AlertSenders` are the provider's security senders plus the domains of `box.PlanSenders(ctx, authServ)`.
   - The host runs that read itself: once after start, again after each account change, and then once a day. It runs in the host's refresh loop (`mailhost.go`), not inside the world function, keeps the domains in memory keyed by `h.changes`, and shares the result with `accountPlan`, so setup does not read the mailbox twice.
   - Until the read has completed in this process for the current account, `AlertSenders` is empty. `guardOff` then holds and nothing is trashed or unsubscribed, which fails closed after every restart until the read completes. A failed read keeps it that way and retries at the next refresh.
   - The world function never calls `accountPlan` or the mailbox, so there is no lock cycle and no recursion.
7. **Wiring.** `cmd/agentos-clerk-mail` passes `Guard` and `DKIM` and stops passing `World`. Update the main's ASSUMPTIONS row MAIL-main-a-5 for the world half.

**Requirement IDs:** VRB-2 (alert guard, DKIM, provider table), D-141, D-154 rules 3 to 5, DEV-2.

**Acceptance tests (a):**
- `clerk/inbox/dkimdns_test.go`:
  - `TestDKIMNamesMatchVerifyOne`: for signatures with a Unicode `d=`, mixed case and a dotted selector, `DKIMNames` gives exactly the map keys `VerifyDKIM` reads, and a key served under each name makes the signature pass. Fails if the two forms drift.
  - `TestLookupDKIMRecords`: a fake resolver serves a good record and each of these bad answers: two DKIM records at one name, `v=DKIM2`, `k=ed25519`, `h=sha1`, `s=tlsrpt`, `t=y`, `t=s:y`, an empty `p=`, bad base64, an oversized answer and an error. Only the good record is kept, and every query it sees ends in a dot.
  - `TestLookupDKIMBounds`: 3 signatures on one mail look up 2 names; 500 names look up 400; a name over 253 bytes, or one with an empty label, is not looked up; a resolver that hangs ends at the per-read bound.
- `clerk/inbox/providers_test.go::TestProviderTables`: the shipped file parses and every line carries a source. `gmail` gives `mx.google.com`, and a host under a listed suffix matches it. A lookalike suffix (`evilgmail.com`, `gmail.com.evil.test`) matches nothing. An unknown host gives `""` and no security senders.
- `clerk/run/world_test.go`:
  - `TestWorldFromOwnSources`: for a Gmail account and an IMAP account on a test-only table, the world has the table's fields, `Today` from the clock, and the `PlanSenders` domains in `AlertSenders` once the read has completed, and has no `History`, `Contacts` or `KnownSenders` (those are slice b's).
  - `TestWorldFollowsTheAccount`: a host started with no account has an empty world. After `setmail` for an IMAP account on the table, the next world has that provider's `AuthServ`. After the account is replaced by another provider's, or by an unknown one, the world has the new provider's values or `""`, never the old ones.
  - `TestGuardStaysOffUntilTheSendersRead`: after a restart, until `PlanSenders` completes, `AlertSenders` is empty and a spam mail is not trashed (`no-alert-guard`). After the read it is trashed. A failing read keeps the guard off.
  - `TestWorldDoesNotWaitOnThePlan`: `accountplan` and a read run at once under `-race`, with no deadlock and one `PlanSenders` read between them.
- `clerk/run/mail_test.go::TestReadUsesItsOwnKeyLookups`: a fake mailbox holds a signed bulk mail, with history from a test world. With `DKIM` serving its key, `Evaluate` gives `ok`. With `DKIM` serving nothing, it gives `dkim-none`. With `DKIM` nil, the test world's own keys are used, and the existing `fixtureWorld` tests pass unchanged.
- `cmd/agentos-clerk-mail/main_test.go::TestTheMailClerkLearnsItsNetwork`: the main's policy has a `Source`. Before any learn, a lookup through it is refused with no query sent, and after a learn only the learned resolver's address is dialled.
- `main_test.go::TestTheMailProcessLinksNoMainSideCode` (existing) still passes.

**Scope (a):**
- `broker/clerk/inbox/`: `dkimdns.go`, `providers.go`, `providers.txt` and their tests; `dkim.go` for the shared name function; ASSUMPTIONS rows.
- `broker/clerk/run/`: `world.go`; `mail.go` for the `DKIM` field and the per-read keys; `mailhost.go` for the refresh loop's senders read and the host's world; `accountplan.go` to share the senders read; tests; ASSUMPTIONS rows.
- `broker/cmd/agentos-clerk-mail/`: `main.go`, `main_test.go`, `ASSUMPTIONS.md`.

**Guard files (a):** none expected. `clerk/inbox` and `clerk/run` already carry `parser` lines and are classed through `core.txt`, and no package is added.

## MAIL-world-b1: the IMAP address-header op

`imapwire` gains `OpAddrHeads`: the `From`, `To` and `Cc` of the given UIDs in a folder at a validity, read with `BODY.PEEK[HEADER.FIELDS (FROM TO CC)]`, bounded per message like `OpPlanHeads` and per batch like `OpSeenBatch`. `imapconn` implements it, and `imapsmtp.Store` gets `AddrHeads(ctx, folder, validity, uids, each)`. Nothing else changes.

**Acceptance tests (b1):** `imapwire` round-trip and bound tests for the new op (a header over the bound names its folder and arrival, as `Seen` does); an `imapconn` test over the loopback server that the op fetches with `BODY.PEEK` and leaves `\Seen` unchanged; an `imapsmtp` test that a missing answer fails the call rather than being skipped.

**Scope (b1):** `broker/clerk/inbox/imapwire/`, `broker/clerk/inbox/imapconn/`, `broker/clerk/inbox/imapsmtp/` (the new method and its tests). **Guard files (b1):** none.

## MAIL-world-b2: history, known senders and contacts from the mailbox

1. **What is read.** History comes only from folders whose role is `Inbox`, `Archive` or `All` (`imapconn.role`; for Gmail, `INBOX` and the messages outside `SPAM`, `TRASH`, `DRAFT` and `SENT`). A folder with no role, such as an unflagged `Spam` or `Junk` folder on a server without SPECIAL-USE or a folder the owner made, never counts as delivered history. For each message the read takes its `From` and its arrival date: IMAP `INTERNALDATE`, which the sender does not set, or Gmail's `internalDate`. From the `Sent` role (Gmail `SENT`) it reads the `To` and `Cc` addresses. Over IMAP it uses `OpUIDs`, `OpDates` and b1's `AddrHeads`; over Gmail, the declared metadata calls that `PlanSenders` uses. No grant scope is added.
2. **Where and when it runs.** A `senders` worker in the host's refresh loop (`mailhost.go`) reads in steps of at most 2,000 messages, 10 s apart, until every counted folder has been read through. After that it runs once per mail read, for UIDs above each folder's high-water mark. So a mailbox of 100,000 messages completes in about 50 steps, under 10 minutes plus read time. A sign-in failure pauses the worker, as it pauses reads.
3. **The record** (`clerk/run/senders.go`) is sealed under the clerk's `Sealer` and bound to the account's slot, with the AAD as in `seen.go`. Its size is checked before it is read, and a record that does not load starts over. It holds:
   - per folder, the UID validity and the highest UID read;
   - per sender (`canonAddr`), the earliest counted date;
   - the set of sent-to addresses.

   A changed validity re-reads that folder.
4. **Bounds and completeness.** The record holds at most 20,000 senders and 5,000 contacts. `History`, `KnownSenders` and `Contacts` stay empty, so VRB-2 stops at `no-history`, in each of these cases:
   - until every counted folder has been read through once;
   - whenever a bound is passed;
   - whenever any folder fails.

   STATUS's existing warm-up line (`MailStatus`) says that unsubscribing waits for the first full read, with no count of mails.
5. **The world.** On a complete record:
   - `History` holds one `Delivery{From, Folder:"inbox", Date}` per sender, at its earliest date; `Evaluate` needs only the earliest counted date;
   - `KnownSenders` is the senders;
   - `Contacts` is the sent-to addresses.
6. **Removal.** `removemail` deletes the record with the settings.

**Requirement IDs:** VRB-2 (history, lookalike, 90-day first mail, read state), D-141, D-154 rule 5.

**Acceptance tests (b2):**
- `clerk/run/senders_test.go`:
  - `TestHistoryFromTheMailbox`: in a fake mailbox, senders appear in the inbox since day 0, in an archive folder, in a `\Junk` folder, in an unflagged folder named `Spam`, in trash and in a folder the owner made. Only the inbox and archive senders get history, each at its earliest date. Fails if junk, or any folder with no role, counts as delivered.
  - `TestContactsAreSentRecipients`: the `To` and `Cc` of sent mail become `Contacts`, and a sender that is a lookalike of one gives `lookalike` in `Evaluate`.
  - `TestIncompleteReadBlanksAll`: each of a folder failing, a bound passed, and a first read not yet through gives a world with all three fields empty, so an otherwise eligible mail gets `no-history` from `Evaluate`.
  - `TestALargeMailboxCompletes`: 9,000 messages complete in 5 steps, and only then is history given.
  - `TestSenderRecordIsSealedAndIncremental`: a second read fetches only new UIDs, and a changed UID validity re-reads the folder. A record sealed under another slot or key, too large or damaged starts over.
  - `TestSendersReadKeepsReadState`: over the loopback IMAP test server, no message's `\Seen` flag changes.
- `clerk/run/mailhost_test.go::TestRemoveMailDeletesTheSendersRecord`: after `removemail`, the record file is gone, and a new account starts its read over.
- `clerk/inbox/gmail_test.go::TestGmailSendersUsesDeclaredCalls`: the Gmail read uses only declared metadata calls and does not count `SPAM`, `TRASH`, `DRAFT` or `SENT` as history.

**Scope (b2):**
- `broker/clerk/run/`: `senders.go`, `world.go`, `mailhost.go`, `mail.go`, tests, ASSUMPTIONS.
- `broker/clerk/inbox/`: `mailbox.go` and `gmail.go`, plus `plansenders.go` only if a helper is shared; tests.

**Guard files (b2):** none.

**Order and conflicts.** a, b1 and b2 run in that order; b1 touches none of a's files and may run beside it. MAIL-world-a and MAIL-reader-sock-a both edit `cmd/agentos-clerk-mail/main.go` and `main_test.go`, so whichever starts second waits for the first's merge (D-111).

**Recurring kinds (reviews/security/README.md, keeper rows):**
- an input taken from the main side (none here; any new field must name its own source);
- a partial answer passing for a full one (each source is all or nothing);
- a date the sender set (only the server's arrival dates count);
- a read that marks mail read;
- settings captured once and served stale.

**Lifecycle (integration owner: MAIL-world-b2).**
- **First boot after setup:** the guard is off until the clerk's first `PlanSenders` read completes, and unsubscribing waits for the first full senders read, with the warm-up line shown.
- **Clerk restart:** the senders record reloads; the DKIM lookups, the tables and the `PlanSenders` read are fresh, and the guard stays off until that read completes.
- **Update:** the record is kept (same key), and a changed shipped table applies at once.
- **Account removed:** `removemail` deletes the record.
- **Account replaced:** a new slot starts over, and the world follows the new settings at its next call.

**Usage estimate:** a: about 120k tokens. b1: about 50k. b2: about 120k.
