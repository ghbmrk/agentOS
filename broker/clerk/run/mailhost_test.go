package run

// REQ: CLK-1, CH-11, VRB-2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// serveMail serves side of h on a fresh socket for the test's uid.
func serveMail(t *testing.T, h *MailHost, side MailSide) Conn {
	t.Helper()
	sock := filepath.Join(shortDir(t), "m.sock")
	ln, err := ListenMail(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServeMail(ln, h, side)
	return Conn{Socket: sock, UID: os.Getuid(), Timeout: 20 * time.Second}
}

// The owner sets up, replaces and removes the account on the mail process's
// own socket, so the password reaches only that process (CLK-1). A refusal
// keeps its wording and changes nothing; each replacement and removal is
// told once, in the old setup's words (CH-11); and the planner's listing
// follows the account, read again on its request.
func TestMailSetupRunsOnTheClerksOwnSocket(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", mailFrom("news@shop.test", "<n1@shop.test>"))
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, mailConfig())
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	planner := MailPlanner{serveMail(t, h, MailPlannerSide)}

	if _, err := planner.Listing(); err == nil || err.Error() != ErrNoMailAccount.Error() {
		t.Fatalf("a listing with no account: %v", err)
	}
	if res := h.Do(kernel.Request{}, nil); res.Outcome != "failed" || res.Detail != DNoAccount {
		t.Fatalf("a step with no account: %+v", res)
	}
	s := MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}
	bad := s
	bad.Address = "Pat <" + imaptest.User + ">"
	if err := owner.SetMail(bad, imaptest.Password); err == nil || err.Error() != ErrMailAddress.Error() {
		t.Fatalf("a refused setup: %v, want %q", err, ErrMailAddress)
	}
	if err := owner.SetMail(s, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	if ls, err := planner.Listing(); err != nil || len(ls) != 1 {
		t.Fatalf("the listing after setup: %v, %v", ls, err)
	}
	st, err := owner.Status()
	if err != nil || len(st.Notices) != 0 || !has(st.Lines, "began its record") {
		t.Fatalf("status after the first setup: %+v, %v", st, err)
	}

	if err := owner.SetMail(bad, imaptest.Password); err == nil {
		t.Fatal("a refused replacement was taken")
	}
	if st, _ := owner.Status(); len(st.Notices) != 0 {
		t.Fatalf("a refused replacement was told as one: %+v", st)
	}
	if err := owner.SetMail(s, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	if st, _ := owner.Status(); len(st.Notices) != 1 || st.Notices[0] != noteMailReplaced {
		t.Fatalf("status after a replacement: %+v", st)
	}
	if st, _ := owner.Status(); len(st.Notices) != 0 {
		t.Fatalf("the replacement was told twice: %+v", st)
	}

	srv.Deliver("INBOX", mailFrom("news@shop.test", "<n2@shop.test>"))
	if ls, _ := planner.Listing(); len(ls) != 1 {
		t.Fatalf("the listing changed before a re-read: %d mails", len(ls))
	}
	if ls, err := planner.Reread(); err != nil || len(ls) != 2 {
		t.Fatalf("the re-read: %d mails, %v", len(ls), err)
	}

	if err := owner.RemoveMail(); err != nil {
		t.Fatal(err)
	}
	if st, _ := owner.Status(); len(st.Notices) != 1 || st.Notices[0] != noteMailRemoved || len(st.Lines) != 0 {
		t.Fatalf("status after the removal: %+v", st)
	}
	if _, err := planner.Listing(); err == nil {
		t.Fatal("a listing after the removal")
	}
	if res := h.Do(kernel.Request{}, nil); res.Detail != DNoAccount {
		t.Fatalf("a step after the removal: %+v", res)
	}
}

// Each mail socket serves its side only: the planner cannot set up, remove or
// read the owner's status, and the owner side's socket has no listing.
func TestEachMailSocketServesOnlyItsSide(t *testing.T) {
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, mailConfig())
	owner := serveMail(t, h, MailOwnerSide)
	planner := serveMail(t, h, MailPlannerSide)
	for _, op := range []string{"setmail", "removemail", "status"} {
		if err := planner.call(op, setMailArgs{Settings: MailSettings{Address: "a@b.test", IMAP: "i.test:993", SMTP: "s.test:465"}, Password: "a-password-12"}, nil); err == nil || !strings.Contains(err.Error(), "no call") {
			t.Fatalf("%s on the planner's socket: %v", op, err)
		}
	}
	for _, op := range []string{"listing", "reread"} {
		if err := owner.call(op, nil, nil); err == nil || !strings.Contains(err.Error(), "no call") {
			t.Fatalf("%s on the owner's socket: %v", op, err)
		}
	}
	if _, err := readMail(dir); !errors.Is(err, ErrNoMailAccount) {
		t.Fatalf("a refused call set up an account (%v)", err)
	}
}
