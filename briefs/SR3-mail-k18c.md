# SR3-mail-k18c: a recovered reader panic must not leave go-imap's state lock held

Board section: Security and architecture review (2026-10-08). Source: PR #1245 L3, Security point 3. Row #1255, class release, tier A.

**Why it matters.** The patched go-imap client (SR3-mail-k18, mail M20) recovers a panic in its reader goroutine, closes the connection and ends. If the panic happens while the reader holds the client's state lock `c.locker`, the lock stays held, and the session's deferred `Logout` in `imapsmtp.sessionN`, which calls `State()`, blocks forever: the mail.sock call is never answered. A refused SELECT reaches this: `Select` sets `c.mailbox` to nil on the caller's goroutine while the reader's unilateral EXISTS or RECENT handler, having seen a non-nil `Mailbox()`, takes the lock and dereferences `c.mailbox`.

**Requirements:** CRED-8 (a hostile server costs one call, not the vault process), CRED-1. Also egress K18 and mail M20 (rows, not SPEC IDs).

**Fix.** In `client/client.go`: EXISTS and RECENT read the selected mailbox once and update that pointer, so a concurrent clear cannot make them dereference nil; `State`, `Mailbox`, `SetState` and `gotStatusCaps` unlock by `defer`. Audit every other section that holds `c.locker` for a panic path. Mirror the edit into `broker/vendor/` (go.mod replaces the module with `third_party/go-imap`, and the build is vendored) and record it in PATCH.md.

**Acceptance tests:** CRED-8: `TestFailedSelectThenExistsAnswers` (`broker/mail/imapsmtp/imapsmtp_test.go`) and `TestHostileSelectCostsOneCall` (`broker/mail/mailsock/mailsock_test.go`).

**Tests first.**
- T1 `TestFailedSelectThenExistsAnswers`: a raw server accepts LOGIN and answers every SELECT with `NO`, with 200 `* 3 EXISTS` / `* 2 RECENT` lines before and after it. Each of 300 `Fetch` calls must return an error within 10 s. On main a call hangs in `Logout`.
- T2 `TestHostileSelectCostsOneCall`: the same server behind mail.sock; each of 100 `UIDs` calls answers `ErrFailed` within 10 s. On main a call hangs.
- Control: existing `broker/mail/...` tests stay green under `-race`.

**Docs.** Mail ASSUMPTIONS: amend M20's #1255 sentence and add M22. Egress ASSUMPTIONS: append K34 replacing K18's #1255 residual.

**Out of scope.** Other response-handler panics (they already cost one call under M20), the in-flight request cap (SR3-mail-k18f).

**Scope:** `broker/third_party/go-imap/client/client.go`, `broker/third_party/go-imap/PATCH.md`, the same two files under `broker/vendor/github.com/emersion/go-imap/`, `broker/mail/imapsmtp/` (test only), `broker/mail/mailsock/mailsock_test.go`, `broker/mail/ASSUMPTIONS.md`, `broker/egress/ASSUMPTIONS.md`, this brief.

**Usage estimate:** 80k tokens, checkpoint at 80k. Builder model: strongest (tier A).
