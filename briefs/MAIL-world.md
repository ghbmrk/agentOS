# MAIL-world: the live mail clerk's VRB-2 world

Work item #3422, filed from [briefs/MAIL-main.md](MAIL-main.md) (PR #3442). Tier A, release. Checked on main at 764887f with #3442's head 1308544. Two slices, one session each, in order; both wait on MAIL-main-a (#3442).

**Why.** `run.MailConfig.World` has no production source. MAIL-main-a's main returns `inbox.World{}`: VRB-2 passes no unsubscribe (no key records: `dkim-none`; no history: `no-history`) and the alert guard's first net (`alertSender`) matches nothing, since `AuthServ` and `AlertSenders` are empty. Both fail closed, but the box never unsubscribes and hides alerts on wording alone. `LastOpened` is already the clerk's own (`clerk/run/seen.go`), and `Today` is this process's clock (D-154 rule 5).

**Standing rules.** D-154 (decisions/D-154.md): the mail clerk is a keeper process. It takes nothing of the world from the main side, and every input below is read by the clerk itself, from the mailbox, its own DNS lookups or a table shipped in its binary. Rule 4 still holds: no new link to main-side code. Every source fails closed. A source that cannot be read in full leaves its fields empty, and the empty field must make VRB-2 refuse rather than pass. The order of VRB-2's clauses guarantees this (`clerk/inbox/vrb2.go` `Evaluate`): an empty `History` stops at `no-history` before the lookalike clause reads `Contacts` and `KnownSenders`, so slice b blanks all three together on any failure.

**Acceptance tests:** per slice, under "Acceptance tests (a)" and "Acceptance tests (b)" below.

## Where each field comes from

| Field | Source | Slice |
|---|---|---|
| `DKIMKeys` | The clerk's own DNS TXT lookups of `<s>._domainkey.<d>` for the signatures on the mails of this read, through the process's netguard resolver | a |
| `ProviderTable` | A table shipped in the binary (`go:embed`): the registrable domains of mail service providers whose unsubscribe hosts VRB-2 accepts | a |
| `AuthServ` | A shipped per-provider table keyed by the account's API or IMAP host suffix. Gmail is `mx.google.com`. Unknown providers get `""`, which matches nothing | a |
| `AlertSenders` | The provider's own security senders, from the same table, plus the domains of the account plan (`MailHost.accountPlan`, the DKIM-authenticated senders of services the owner holds accounts with) | a |
| `History`, `KnownSenders`, `Contacts` | The mailbox: earliest delivery per sender outside junk and trash, the set of those senders, and the recipients of the owner's sent mail, kept in a sealed incremental record | b |
| `Today`, `LastOpened` | Unchanged: own clock, own sealed record | none |

Senders the owner marks as financial or identity have no owner surface on the new core. That part of SPEC's alert rule is out of scope here; the builder of slice a files it as a `class:later` issue tagged `recheck` (the second net, the wording patterns, still applies).

## MAIL-world-a: key records, shipped tables and alert senders

1. **The process's network policy.** MAIL-main-a's main leaves `MailConfig.Guard` nil, and `imapsmtp` and `gmailNet` then use `netguard.New(netguard.Config{})`. That policy learns no network, and "nothing learned means nothing resolves" (`netguard/resolver.go`), so on a real box no name resolves: not Gmail's, not the IMAP server's, not a DKIM record. The main builds one policy the way `cmd/agentos-egress/netguard.go` `netGuard` does (`netguard.Sources`, `Refresh`, `WatchEventsEvery` with `netguard.WatchNetlink`, no pins, refusals logged by address and reason only) and passes it as `MailConfig.Guard`. Copy the function; do not import `cmd/agentos-egress`. If the unit's sandbox (MAIL-unit) cannot read the routes or open netlink, the first read logs and the poll retries, as in egress; record that in ASSUMPTIONS.
2. **Key lookups per read.** Add `inbox.DKIMNames(raw []byte) []string`: the lookup name `s + "._domainkey." + alabel(d)` of each `DKIM-Signature` that `sigTags` parses, in the exact form `verifyOne` looks up (one function, used by both, so the two cannot drift). `MailConfig` gains `DKIM func(ctx context.Context, names []string) map[string]string`. `openMail` collects the names from the mails it read, calls `DKIM` once, and its per-read world closure sets `DKIMKeys` the way it already sets `LastOpened`. Every judgement in that read therefore sees one fixed set of keys. When `DKIM` is nil, `DKIMKeys` is empty (tests, and the fail-closed default).
3. **The lookup** (`clerk/inbox/dkimdns.go`, in the package that already carries a `parser` line): `LookupDKIM(ctx, r *net.Resolver, names)` through `Guard.Resolver()`. Bounds: at most 2 names per mail and 400 names per read (later names are skipped, so their signatures fail), names of at most 253 bytes made of valid labels only, 5 s per lookup and 30 s per read, and at most 8 KiB of TXT per name. A name's record is the TXT strings of one record joined, and the lookup keeps the `p=` value only when all of these hold:
   - exactly one TXT record at the name parses as DKIM (two or more is ambiguous, so the name is absent);
   - `v=`, if present, is `DKIM1` and comes first;
   - `k=`, if present, is `rsa`;
   - `h=`, if present, lists `sha256`;
   - `t=` has no `y` (RFC 6376 §3.6.1: a test-mode key counts as unsigned);
   - `p=` is non-empty (an empty one is revoked) and base64.

   Any lookup error leaves the name absent. A failed lookup is never retried within the read.
4. **The shipped tables** (`clerk/inbox/providers.go`, `go:embed providers.txt`): a line-based file with three kinds of line:
   - `esp <domain>`: a provider-table domain;
   - `authserv <api-or-imap-host-suffix> <id>`;
   - `security <api-or-imap-host-suffix> <address-or-domain>`.

   Each line ends with a `-- <source>` comment naming the provider's documentation or a header sample. The file is parsed at init, and a bad line panics at test time. The table holds Gmail and the providers the builder can cite. An entry that cannot be cited is left out, which fails closed. Lookup by host suffix uses A-label, dot-bounded matching, so `evilgmail.com` does not match `gmail.com`. The eval's `mailhub.test` entries go in tests only, never in the shipped file.
5. **Assembly** (`clerk/run/world.go`): `World(s MailSettings, plan func() []string)` returns the `func() inbox.World` the main passes. It fills `Today` (own clock), `ProviderTable`, `AuthServ` and `AlertSenders` (the provider's security senders plus `plan()`). `plan()` returns the domains of the last account plan built, empty until one is, with no new mailbox read. Because `accountPlan` reads `AuthServ` from this world, the world must not call back into `accountPlan`: it reads the cached plan only (no lock cycle, no recursion). A test proves this under `-race`.
6. **Wiring.** `cmd/agentos-clerk-mail` passes `Guard`, `DKIM` and `World`. The main's ASSUMPTIONS row MAIL-main-a-5 is updated for the world half.

**Requirement IDs:** VRB-2, D-141, D-154 rules 3 to 5, DEV-2.

**Acceptance tests (a):**
- `clerk/inbox/dkimdns_test.go::TestDKIMNamesMatchVerifyOne`: for signatures with a Unicode `d=`, mixed case and a dotted selector, the names `DKIMNames` returns are exactly the map keys `VerifyDKIM` reads. A key served under each name makes the signature pass. Fails if the two forms drift.
- `dkimdns_test.go::TestLookupDKIMRecords`: a fake resolver serves one good record, two DKIM records at one name, `v=DKIM2`, `k=ed25519`, `h=sha1`, `t=y`, `t=s:y`, an empty `p=`, bad base64, an oversized answer and an error. Only the good record is kept.
- `dkimdns_test.go::TestLookupDKIMBounds`: 3 signatures on one mail look up 2 names, 500 names look up 400, a name over 253 bytes or with an empty label is not looked up, and a resolver that hangs ends at the per-read bound.
- `clerk/inbox/providers_test.go::TestProviderTables`: the shipped file parses, every line carries a source, `gmail` gives `mx.google.com`, a host under a listed suffix matches it, a lookalike suffix (`evilgmail.com`, `gmail.com.evil.test`) matches nothing, and an unknown host gives `""` and no security senders.
- `clerk/run/world_test.go::TestWorldFromOwnSources`: for a Gmail account and an IMAP account on a test-only table, the world has the table's fields, `Today` from the clock, the plan's domains in `AlertSenders`, and no `History`, `Contacts` or `KnownSenders` (slice b).
- `world_test.go::TestWorldDoesNotWaitOnThePlan`: `accountplan` and a read run at once under `-race`, with no deadlock and no second mailbox read.
- `clerk/run/mail_test.go::TestReadUsesItsOwnKeyLookups`: a fake mailbox with a signed bulk mail, and `DKIM` serving its key, gives `ok` from `Evaluate` (with history from a test world). With `DKIM` nil, or serving nothing, it gives `dkim-none` or `dkim-fail`. Fails if keys come from anywhere but the read's own lookups.
- `cmd/agentos-clerk-mail/main_test.go::TestTheMailClerkLearnsItsNetwork`: the main's policy has a `Source`, and before any learn a lookup through it is refused, not answered by the system resolver (`/etc/resolv.conf` is never read).
- `main_test.go::TestTheMailProcessLinksNoMainSideCode` (existing) still passes.

**Scope (a):** `broker/clerk/inbox/` (`dkimdns.go`, `providers.go`, `providers.txt` and their tests; `dkim.go` for the shared name function; ASSUMPTIONS rows), `broker/clerk/run/` (`world.go`, `mail.go` for the `DKIM` field and the per-read keys, tests, ASSUMPTIONS rows), `broker/cmd/agentos-clerk-mail/` (`main.go`, `main_test.go`, `ASSUMPTIONS.md`).

**Guard files (a):** none expected. `clerk/inbox` and `clerk/run` already carry `parser` lines and are classed through `core.txt`, and no package is added. If the builder adds a package, it adds that package's `parser` line to `tools/trusted_base_parsers.txt` (pre-approved) and checks `python3 tools/risk_tier.py` classes it A.

## MAIL-world-b: history, known senders and contacts from the mailbox

1. **The read.** A new `mailbox` method, `Senders(ctx, rec SenderLog) (SenderLog, error)`, is implemented by `inbox.Live` and `inbox.Gmail`. It reads, for every folder except junk, spam and trash (the folders `PlanSenders` already skips, by special-use flag or Gmail label), each message's `From` and arrival date (IMAP `INTERNALDATE`, which the sender does not set; Gmail `internalDate`). From the Sent folder (`\Sent`, Gmail `SENT`) it also reads the `To` and `Cc` addresses. Headers are read with `BODY.PEEK`, so the read state is unchanged (VRB-2 "Read state"). Over IMAP, use the existing typed ops (`OpUIDs`, `OpDates`, and a header fetch). If no existing op fetches `To` and `Cc`, add one op to `imapwire` and `imapconn` (`OpAddrHeads`: `From`, `To`, `Cc` of UIDs, bounded like `OpPlanHeads`). Over Gmail, use the declared metadata calls `PlanSenders` uses. No new scope is added to the grant.
2. **The record** (`clerk/run/senders.go`): sealed under the clerk's `Sealer`, bound to the account's slot (AAD as in `seen.go`), with its size checked before it is read. Per folder it holds the UID validity and the highest UID read. Per sender (canonical address, `canonAddr`) it holds the earliest non-junk date. It also holds the set of sent-to addresses. Each read adds only UIDs above the high-water mark. A changed validity re-reads that folder. A record that does not load starts over.
3. **Bounds and completeness.** A single read takes at most 2,000 messages (it resumes at the next read) and the record holds at most 20,000 senders and 5,000 contacts. Until every folder has been read through once, and whenever a bound is passed or any folder fails, the world's `History`, `KnownSenders` and `Contacts` are all empty (VRB-2 stops at `no-history`). STATUS's existing warm-up line (`MailStatus`) says that unsubscribing waits for the first full read. The owner is not told a count of mails.
4. **The world.** On a complete record, `History` holds one `Delivery{From, Folder:"inbox", Date}` per sender, at its earliest date. `Evaluate` needs only the earliest non-junk date, so one entry per sender is enough. `KnownSenders` is the senders. `Contacts` is the sent-to addresses.

**Requirement IDs:** VRB-2 (history, lookalike, 90-day first mail, read state), D-141, D-154 rule 5.

**Acceptance tests (b):**
- `clerk/run/senders_test.go::TestHistoryFromTheMailbox`: a fake mailbox with a sender in the inbox since day 0, one only in junk, one only in trash, and one in an archive folder. Only the inbox and archive senders get history, each at its earliest date. Fails if junk counts as delivered.
- `senders_test.go::TestContactsAreSentRecipients`: `To` and `Cc` of sent mail become `Contacts`, and a sender lookalike of one is `lookalike` in `Evaluate`.
- `senders_test.go::TestIncompleteReadBlanksAll`: a folder failing, a bound passed, and a first read not yet through each give a world with all three fields empty, and `Evaluate` gives `no-history` for a mail that is otherwise eligible.
- `senders_test.go::TestSenderRecordIsSealedAndIncremental`: a second read fetches only new UIDs. A changed UID validity re-reads the folder. A record sealed under another slot or key, too large or damaged starts over.
- `senders_test.go::TestSendersReadKeepsReadState`: over the loopback IMAP test server, no message's `\Seen` flag changes.
- `clerk/inbox/gmail_test.go::TestGmailSendersUsesDeclaredCalls`: the Gmail read uses only declared metadata calls and skips `SPAM` and `TRASH`.
- If `OpAddrHeads` is added: `clerk/inbox/imapwire` round-trip and bound tests, and an `imapconn` test that it fetches with `BODY.PEEK`.

**Scope (b):** `broker/clerk/run/` (`senders.go`, `world.go`, `mail.go`, tests, ASSUMPTIONS), `broker/clerk/inbox/` (`mailbox.go`, `gmail.go`, and `plansenders.go` only if a helper is shared; tests), `broker/clerk/inbox/imapsmtp/`, `broker/clerk/inbox/imapwire/` and `broker/clerk/inbox/imapconn/` (one op, only if needed).

**Guard files (b):** none; no package is added.

**Recurring kinds (reviews/security/README.md, keeper rows):** an input taken from the main side (none here; any new field must name its own source); a partial answer passing for a full one (each source is all or nothing); a sender-set date (only server arrival dates count); a read that marks mail read.

**Lifecycle (integration owner: MAIL-world-b).** First boot after setup: no record, so the warm-up line shows and nothing is unsubscribed until the first full read. Clerk restart: the record reloads, and the DKIM lookups and tables are fresh. Update: same record (same key); a changed shipped table applies at once. Account removed: `removemail` deletes the record with the settings (b adds `senders` to the files `removemail` clears, with a test). Account replaced: a new slot starts over.

**Usage estimate:** a: about 110k tokens. b: about 140k tokens (the IMAP op is most of it; split it off as b2 if it is needed and the session passes 100k before it starts).
