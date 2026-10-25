# TN-shadow: the shadow week's read-only mode, log and read-back

Board row: issue #2878 (D-152 item 2, EVL-2). Tier A (`broker/clerk/inbox`). Release.

## Problem

D-152 says the slice runs on the owner's real mailbox for seven days, read-only, before any task changes it. Nothing on main can do that: the mail clerk's Gmail declaration includes writes, the clerk keeps no record of what it would have done beyond one run, and nothing reads back what the owner did with each mail. The run itself is gated on G1 on the M6 Ultra and the mail clerk's process wiring (the serial `cmd/agentosd` chain). This package builds the parts that need neither, so the week can start as soon as the box runs.

## Design

- **Read-only grant.** `GmailReadCalls` is `GmailCalls` minus every call that is not a GET: label, trash, untrash, label create and send are undeclared, so the exit refuses them before any request (CLK-3). The grant is the existing `archive` use, `gmail.readonly`, which cannot change a mail; the owner page's wording for the week is TN-shadow-run's.
- **Effects never sent.** The shadow run's clerk lands its effects on `Synthetic`, which accepts every effect and sends nothing, so an unsubscribe POST never leaves the box. The clerk's own record (`Effects`) is what it would have done.
- **The log.** `Shadow` holds the week's start and one `Proposal` per mail read: the mail, its class, the slice's verb (`trash`, `unsubscribe`, `organize`, or `leave` when no effect touched it; the strongest when several did) and when. A mail read again later in the week keeps its first proposal. Nothing is proposed after the week ends. It marshals to JSON for the clerk process to seal (wiring is TN-shadow-run).
- **Next-day read-back.** A day after each proposal, `ReadBack` asks the mailbox what the owner did with the mail: `removed` (in trash or spam, or gone), `archived` (out of the inbox), `read` (still in the inbox, read) or `unread` (still in the inbox, unread). It reads each proposal once; a failed read is retried on the next call, and a dead grant stops the pass. `Gmail.Owner` reads it from the metadata get's label ids, a read the read-only grant allows.
- **Agreement.** Only a mail the owner acted on counts (read, moved or removed; `unread` is "not looked at"). `trash` agrees when the owner removed it; `unsubscribe` when the owner removed or archived it; `organize` and `leave` when the owner did not remove it.
- **STATUS.** `Line` is one line: agreement by class over the mails the owner looked at, how many they have not looked at yet, and that nothing was changed.

## Requirements (local IDs; SPEC EVL-2)

- **TN-shadow-a.** A Gmail mailbox over the read-only declaration refuses every write before any request reaches the API, and a shadow run (clerk over `Synthetic`, mails read through it) leaves every mail as it was while still recording each effect.
- **TN-shadow-b.** One proposal per mail read, the strongest verb, first proposal kept, none after seven days.
- **TN-shadow-c.** The read-back happens only a day after each proposal, reads the owner's action from Gmail's labels (trash, spam, gone, archived, read, unread), and retries a failed read.
- **TN-shadow-d.** Agreement and the STATUS line follow the rule above, by class.

## Acceptance tests

**Acceptance tests:** TN-shadow-a `broker/clerk/inbox::TestShadowRunChangesNothing`; TN-shadow-b `TestShadowProposesOncePerMail`; TN-shadow-c `TestShadowReadsBackTheOwnersActionADayLater`, `TestShadowRetriesAFailedReadBack`; TN-shadow-d `TestShadowAgreementByClass`.

## Scope

`broker/clerk/inbox/shadow.go` (new), `broker/clerk/inbox/shadow_test.go` (new), `broker/clerk/inbox/gmail.go` (`GmailReadCalls`, `Gmail.Owner`), `broker/clerk/inbox/gmailtest/gmailtest.go` (`Move`, the owner moving a mail), `broker/clerk/inbox/ASSUMPTIONS.md` (TN-shadow rows), this brief. Out of scope: the clerk process and agentosd wiring, sealing the log, the local reader and the week on the M6 Ultra (TN-shadow-run, gated on G1).
