# SR3-mail-k18: the vault process and a panic in go-imap's reader goroutine

Board section: Security and architecture review (2026-10-08). Source: #643 release point 4 (SR3-mail-w1), restated as agentosd ASSUMPTIONS MW8; L3 on #1231 reproduced the panic. Row #789, tier B. `broker/go.mod` is in scope, so the builder re-runs `tools/risk_tier.py`; if it prints A, stop and hand off.

**Why it matters.** egress ASSUMPTIONS K18 says a panic while serving a call "answers `failed` and the vault keeps serving". That holds only on the call goroutine: `mailsock.answer` (broker/mail/mailsock/mailsock.go:~128) recovers there. `imapsmtp` uses go-imap v1.2.1, whose `Client.reader` (client/client.go:131, started at :517 after the greeting) has no `recover` and runs every response handler on that goroutine. A panic there ends the whole vault process, which holds the credentials, model route and texting account; the vault then needs an owner unlock again. The server's bytes are attacker-influenced (a hostile or compromised mail host).

**Established (outcome 1 holds).** A bare `* 1 FETCH\r\n` during `imapsmtp`'s `UidFetch` (imapsmtp.go:290) makes `responses.Fetch.Handle` read `fields[1]` after checking only `len(fields) < 1` (responses/fetch.go:21-30): `index out of range [1] with length 1` on the reader goroutine. It is a field-count bug, not a framing bug, so validating framing or literal size does not catch it, and `client.New` starts the reader itself, so imapsmtp cannot recover it from outside. The builder re-verifies with `imap.ReadResp` plus `(&responses.Fetch{}).Handle`.

**Requirements:** CRED-1 (vault keeps the credential, fails closed), CRED-8 (unlock stays an owner act), ARC-2 (agentosd links no inference). Also `broker/mail` ASSUMPTIONS M1 (custody split; a row, not a SPEC ID).

**Guard (preferred, smallest that covers every handler panic).** A `replace` in `broker/go.mod` to a minimally patched copy of go-imap v1.2.1 (vendored directory in the repo, with the upstream licence and a one-line patch note) whose `reader()` recovers, closes the connection and lets the in-flight call fail, which `mailsock` answers `failed`. The patch is only the `recover` in `reader()`; no handler is edited. Alternative, only if the replace route is refused by review: a wrapping `net.Conn` that re-parses each response with `imap.ReadResp` and drops the connection on any response a registered handler would index past. It must track go-imap's handlers, so it is the weaker choice. A process split (mail Store in a child process) is out of scope: stop and escalate, since it changes the custody boundary.

**Read list.** go-imap v1.2.1 `client/client.go` (`reader`, `readOnce`, `handle`), `responses/*.go`, and `message.go` (`Message.Parse`, `BodyStructure.Parse`); all run on the reader goroutine.

**Tests first.** A fake server on `mailtest` or a raw `net.Listener` sending crafted replies.
- T1: `* 1 FETCH\r\n` during a UID fetch. On main it ends the test process (run it in a subprocess to show that, cite the panic). After the guard the call returns an error that `mailsock` answers `failed`, and the process lives.
- T2: `FuzzIMAPReplies`, seeded with T1 and more streams (oversized literal, nested lists, truncated literal, NUL, huge number tokens, untagged responses mid-command); CI runs the seed corpus. Every stream ends in an error, never a dead process.
- T3: after a guarded panic, a second call on the same `mailsock` listener is answered normally.
- Control: existing `broker/mail/imapsmtp` and `mailsock` tests, `TestDaemonAndVaultProcessLinkNoScanner` and the ARC-2 tests stay green.

**Docs.** Update egress K18 and agentosd MW8 (strike MW8 with a pointer) to say what is guarded and how. Add the patched module to `broker/mail/ASSUMPTIONS.md` with "If it changes": drop the replace when upstream recovers or a v2 client replaces it.

**Out of scope.** OAuth, SMTP paths, SR3-mail-w1 l1/l3 LATER items, any agentosd change.

**Scope:** `broker/mail/imapsmtp/`, `broker/mail/mailsock/` tests, `broker/go.mod`, `broker/go.sum`, the patched go-imap directory, `broker/egress/ASSUMPTIONS.md` (K18), `broker/cmd/agentosd/ASSUMPTIONS.md` (MW8), `broker/mail/ASSUMPTIONS.md`.

**Usage estimate:** 100k tokens, checkpoint at 100k. Builder model: Sonnet-class if risk_tier prints B.
