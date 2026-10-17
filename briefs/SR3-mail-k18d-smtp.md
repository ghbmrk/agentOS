# SR3-mail-k18d-smtp: bound what a hostile SMTP server's replies can cost

Board section: Security and architecture review (2026-10-08). Source: PR #1658 L3 (https://github.com/ghbmrk/agentOS/pull/1658#issuecomment-6174075342). Row #1671, class release, tier A.

**Why it matters.** `imapsmtp.Submit` reads SMTP replies through `net/smtp`, whose textproto `ReadResponse` bounds neither a line (`readLineSlice(-1)`) nor the continuation lines of one reply. A hostile or compromised mail host that never ends a reply makes the vault process buffer every byte until the call's 60 s timeout. SR3-mail-k18b (#1254, mail M21) bounded IMAP sessions with `budgetConn`; SMTP was left out.

**Requirements:** CRED-8 (unlock stays an owner act: a hostile server costs one call, not the vault process), CRED-1. Also egress K18 and mail M21 (rows, not SPEC IDs).

**Fix.** Wrap the dialed SMTP connection in `budgetConn` with a fixed budget (1 MiB) for the whole session, under TLS: in implicit-TLS mode `tls.Client` wraps the budgeted conn, so net/smtp still sees a `*tls.Conn` and allows PLAIN and XOAUTH2; `smtp.Client.StartTLS` wraps the client's conn, so after an upgrade the budget also stays under TLS and counts the handshake.

**Acceptance tests:** CRED-8, CRED-1: `TestHostileSMTPReplyIsBounded` and `TestSMTPSubmitWithinBudget` (`broker/mail/imapsmtp/bounds_test.go`).

**Tests first.**
- T1 `TestHostileSMTPReplyIsBounded`: a raw server floods the greeting, the EHLO reply or the MAIL reply, as one endless line or as endless continuation lines. On main each call runs to the timeout; after the fix it fails fast, the server's bytes written stay near the budget, and the call's allocation and peak heap stay a small multiple of it.
- T2 `TestSMTPSubmitWithinBudget`: an ordinary submission (greeting, EHLO, AUTH, MAIL, RCPT, DATA, QUIT) still succeeds, in plain mode on loopback and over implicit TLS (port 465) with PLAIN auth to a non-loopback name. T1 also runs its floods over implicit TLS.
- Control: existing `broker/mail/...` tests stay green.

**Docs.** Extend mail ASSUMPTIONS M21 with the SMTP budget and what it rests on; add the SMTP budget to egress K18's bound sentence.

**Out of scope.** The in-flight request cap (SR3-mail-k18f), go-imap's state-lock hang (SR3-mail-k18c), other k18d later points.

**Scope:** `broker/mail/imapsmtp/`, `broker/mail/ASSUMPTIONS.md` (M21), `broker/egress/ASSUMPTIONS.md` (K18), this brief.

**Usage estimate:** 60k tokens, checkpoint at 60k. Builder model: strongest (tier A).
