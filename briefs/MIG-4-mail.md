# MIG-4-mail-b: delete `broker/mail` and the vault process's mailbox

Work item #2574 (part b; part a, the clerk's live mailbox, merged). One slice, one session: #3679. Tier A. Written 2026-10-28 against main at ed2f1af. Its sibling brief is `briefs/MIG-4-exit.md`; this slice runs before every slice there, since both edit `cmd/agentos-egress`.

## What main shows

- **Nothing in production uses the old mailbox.** `cmd/agentos-egress/mailaccount.go` serves `/mail`, `/mail/status` and `/mail/remove` on the unlock socket and the mail account on `mail.sock`, but no client of either is left: `localui`, `localsrv`, `cmd/agentos-localui` and `cmd/agentosd` dial neither (`grep -rn '"/mail\|mail.sock\|mailsock'` outside `broker/mail` and `cmd/agentos-egress` finds nothing). The owner's mail now runs through the mail clerk (`cmd/agentos-clerk-mail`, MAIL-main).
- **`broker/mail` is only shims and old engine.** `mail/imapsmtp` and `mail/mailtest` are 2574a's shims over `clerk/inbox/imapsmtp` and `imapconn`. `mail` itself still imports `journal`, `recall`, `events`, `grants`, `verb` and `durable` (`go list -deps ./mail/...`), which keeps #3425 (MIG-4-adapters-b, delete `recall` and `events`) blocked.
- **Importers on main:** `cmd/agentos-egress` (`mailaccount.go`, `mailaccount_test.go`, the `serveMail` call in `main.go`, `mailRoutes` in `server.go`); `localui/imports_test.go` (a fence naming `broker/mail` as a forbidden import); `mail/mailsock` and `mail`'s own tests. `vm/gvisor` and `corpus` no longer import it.

## The slice

**Scope:**
- delete `broker/mail/` (with `imapsmtp/`, `mailsock/`, `mailtest/`, `ASSUMPTIONS.md`);
- `broker/cmd/agentos-egress/`: delete `mailaccount.go` and `mailaccount_test.go`; drop the `serveMail` block in `main.go` and the `mailRoutes` line in `server.go`, and any test that only drives them;
- `broker/localui/imports_test.go`: drop the two `broker/mail` fence entries and their comment lines;
- `broker/daemon/arc2_test.go`: only the two comments naming mail in agentos-egress (lines 101 and 344 on ed2f1af), if the test still reads true without them;
- `tools/trusted_base_parsers.txt` (the `mail`, `mail/imapsmtp` and `mail/mailsock` lines), `tools/assumptions_legacy_ids.txt` (the `broker/mail/ASSUMPTIONS.md` M1 to M22 lines), `tools/g1_scope_g2.txt` (`allow broker/mail/`);
- `docs/migration/cases.md`: none edited; the PR names the §7 "Mail through the vault (SR3-mail)" cases it retires and, for each case the mail clerk keeps, the `clerk/inbox` test that already covers it.

**Not in scope:** `clerk/inbox`, `cmd/agentos-clerk-mail` and anything else in `cmd/agentos-egress`. Delete only; add no adapter (#2578 rules).

**Needs:** nothing unmerged. D-111 against the open PRs at 13:40Z: none touches `broker/mail`, `cmd/agentos-egress/{mailaccount,main,server}.go`, `localui/imports_test.go` or `daemon/arc2_test.go`. #3633 holds `tools/g1_scope_g2.txt`, so the build waits for it to merge (it is a one-line exemption PR) or for its own check to say a stale `allow` line is harmless, in which case that line moves to MIG-4-exit-d2. #3624 holds `cmd/agentos-egress/rotwire_test.go` only, which this slice does not touch.

**Requirement IDs:** none changes behaviour: the old mailbox has no caller. Record nothing in an ASSUMPTIONS file; the deleted rows leave with their file.

**Guard files:** `tools/trusted_base_parsers.txt`, `tools/assumptions_legacy_ids.txt`, `tools/g1_scope_g2.txt` and `broker/daemon/arc2_test.go` are gate files, so the PR needs the separate Security accept (D-137).

**Acceptance tests:** `cd broker && go list ./... | grep -c 'broker/mail\b'` prints 0; `grep -rn '"github.com/ghbmrk/agentos/broker/mail' broker --include=*.go` finds nothing; `go vet ./...`, `go test ./cmd/agentos-egress/... ./localui/... ./daemon/...` and `python3 tools/trace.py --ratchet` pass (catches a deleted test whose REQ marker was the last cover of an ID still in SPEC v1.0: re-home that marker on the `clerk/inbox` test that covers it). Then comment on #3425 that `mail` no longer imports `recall` or `events`.

**Size:** S (mostly deletion, about 7.8k lines).
