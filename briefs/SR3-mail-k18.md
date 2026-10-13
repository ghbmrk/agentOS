# SR3-mail-k18: the vault process and a panic in go-imap's reader goroutine

Board section: Security and architecture review (2026-10-08). Source: #643 release point 4 (SR3-mail-w1), restated as agentosd ASSUMPTIONS MW8. Row #789, tier B (the builder runs `tools/risk_tier.py`; if it prints A, stop and hand off).

**Why it matters.** egress ASSUMPTIONS K18 says a panic while serving a call "answers `failed` and the vault keeps serving". That holds only on the call goroutine: `mailsock.answer` (broker/mail/mailsock/mailsock.go:~128) recovers there. `imapsmtp` uses go-imap v1 (`client.New` starts a reader goroutine that parses the server's bytes). A panic in that goroutine cannot be recovered by the caller and ends the whole vault process, which holds the credentials, the model route and the texting account; the vault then needs an owner unlock again. The server's bytes are attacker-influenced (a hostile or compromised mail host). K18 must either be true or say it is not.

**Requirements:** CRED-1 (vault keeps the credential, fails closed), CRED-8 (unlock stays an owner act), ARC-2 (agentosd links no inference), M1 (custody split, broker/mail/ASSUMPTIONS).

**Decision rule for the builder (first step, under 20k tokens).** Read go-imap v1.2.1 `client/client.go` (`receiver`, `handle`) and `imap`'s response/literal parsers. Then pick one outcome and record it in the PR:
1. **A panic is reachable from server bytes** (shown by a failing test): add the smallest guard that keeps the vault process alive. Preferred order: (a) a panic-free wrapper on the connection handed to `client.New` (for example validating framing/literal size before go-imap sees it), (b) a recover-and-restart of the call inside `imapsmtp` if the reader goroutine can be driven from a goroutine we start. A process split (mail Store in its own child process) is out of scope: stop and escalate with a diagnosis, because it changes the custody boundary.
2. **No panic found** (a fuzz run of 60 s over a fake IMAP server's reply stream finds none, and the code read shows only error returns): keep the code, correct K18 and MW8 to say exactly what is and is not guarded, and pin the claim with the fuzz target in CI's short run.

**Tests first.** Build the fake server on `mailtest` or a raw `net.Listener` that sends crafted replies (oversized literal, nested parenthesised lists, truncated literal, NUL, huge number tokens, unsolicited untagged responses mid-command).
- T1: each crafted stream through `imapsmtp.Store` returns an error (`failed`) and the test process lives. Outcome 1 needs one that fails on main first; cite the panic.
- T2: a `testing` fuzz target `FuzzIMAPReplies` seeded with T1's streams; CI runs the seed corpus.
- T3 (outcome 1 only): after the guarded panic, a second call on the same `mailsock` listener is answered normally.
- Control: existing `broker/mail/imapsmtp` and `mailsock` tests, `TestDaemonAndVaultProcessLinkNoScanner`, ARC-2 tests stay green.

**Docs.** Update egress K18 and agentosd MW8 (strike through MW8 with a pointer if resolved) to match the outcome. Add the package's own `ASSUMPTIONS.md` row stating which outcome and why.

**Out of scope.** OAuth, SMTP reader paths (net/smtp has no reader goroutine), SR3-mail-w1 l1/l3 LATER items, any agentosd change.

**Scope:** `broker/mail/imapsmtp/`, `broker/mail/mailsock/` tests, `broker/egress/ASSUMPTIONS.md` (K18 row), `broker/cmd/agentosd/ASSUMPTIONS.md` (MW8 row), `broker/mail/ASSUMPTIONS.md`.

**Usage estimate:** 120k tokens, checkpoint at 100k. Builder model: Sonnet-class if risk_tier prints B.
