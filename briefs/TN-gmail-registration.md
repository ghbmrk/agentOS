# TN-gmail-registration: keep the household's Google registration apart from any grant

Board row: issue #3055 (split from #3030 item 2; Potency R1 on #3027, issuecomment-6388749065; OWN-13, TN-gmail-socket-a). Tier A (`broker/clerk/run`, a clerk process's wiring). Release.

## Problem

The household's Google OAuth registration (client ID and secret, D-150) is sealed only inside a Gmail grant (`clerk.SignIn.Finish` writes `refresh_token`, `client_id`, `client_secret` into the account's slot). Removing the Gmail account, switching to IMAP or `gmailrevoke` drops the slot, and the owner must enter the registration again on the next sign-in. Failure path: an owner who switches to IMAP and back is asked for a registration they already gave.

## Design

- **Where it is sealed.** In its own file `gmail.reg` in the mail clerk's directory, beside `secrets` and `seen.log`, sealed under `MailConfig.Sealer` with its own AAD (`agentOS gmail registration\n`), as `seen.log` already is (#2684). It is not a slot of the `clerk.Secrets` store, so `RemovePrefix(MailSlots, …)` in `SetMail`/`SetGmail` and `RemoveMail` never touch it, and `gmailrevoke`, which ends a grant, keeps it: the registration is the household's app, not an account's grant.
- **CLK-1.** `clerk.NewAPI` and `clerk.NewSignIn` refuse a store holding a second slot. A registration slot inside the mail store would fail both checks for every Gmail account, so the registration stays outside the store, which keeps holding its one account's secret only. No `broker/clerk` code changes, so the trusted core (tools/trusted_core.txt roots) does not grow and D-159 rule 2 needs no card.
- **What is kept.** After a sign-in sets up a Gmail account (first or again), the registration of the grant just sealed (the `client_id` and `client_secret` `SignIn.Saved` hands over, inside the mail process) replaces `gmail.reg`. So a sign-in with a new registration replaces the kept one, and an account set up before this change backfills it at its next sign-in. A failed write leaves the account set up and is reported as the write's later step is today.
- **How a sign-in again picks it up.** `gmailbegin` with no registration: a Gmail account set up with its grant signs in again with that grant's registration, as now; otherwise a `gmail.reg` that loads starts a first sign-in (own in-memory store) with the kept registration; otherwise `DNoAccount`, as now, so the page asks for it. The registration never returns to the main side (D-154 rule 1).
- **Fail closed.** A `gmail.reg` that is not the clerk's own private file, is over 4 KiB, does not open under this sealer and AAD, or holds no ID and secret counts as missing: the owner enters the registration again. No file holds the client secret in the clear.

## Requirements (local IDs, no SPEC row)

- **TN-gmail-registration-a.** Removal, a switch to IMAP and `gmailrevoke` keep the registration; the next `gmailbegin` with none given starts a sign-in whose consent address carries the kept client ID, and its Finish sets the account up.
- **TN-gmail-registration-b.** The registration is sealed apart: the store holds only the account's slot after a sign-in, no file holds the client secret in the clear, and a `gmail.reg` sealed for another purpose or tampered with counts as missing (`DNoAccount`).
- **TN-gmail-registration-c.** A sign-in with a new registration replaces the kept one.

## Acceptance tests

**Acceptance tests:** TN-gmail-registration-a `broker/clerk/run::TestARegistrationOutlivesItsAccount`; TN-gmail-registration-b `TestTheRegistrationIsSealedApart`; TN-gmail-registration-c `TestANewRegistrationReplacesTheKept`.

## Scope

`broker/clerk/run/gmailsignin.go`, `broker/clerk/run/gmailreg.go` (new), `broker/clerk/run/gmailreg_test.go` (new), `broker/clerk/run/ASSUMPTIONS.md` (TN-gmail-registration row; TN-gmail-socket-a's last sentence), this brief. Out of scope: the Connect page (#3060) and erase (#2823), which drops `gmail.reg` with the rest of the clerk's directory.
