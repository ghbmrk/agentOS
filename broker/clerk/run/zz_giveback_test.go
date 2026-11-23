package run

// REQ: CLK-9, CLK-1, A22

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// restart is the mail process started again over dir after a crash: a
// store read back from disk and a new host, which settles the record of
// grants owed a give-back before it reads.
func restart(t *testing.T, dir string, c MailConfig) (*MailHost, *clerk.Secrets) {
	t.Helper()
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	return NewMailHost(context.Background(), dir, sec, c), sec
}

// otherGrant is a grant for another Google account, which the fake does
// not know: its revocation is answered 400, as Google answers a grant it
// no longer knows, and ends no other grant.
func otherGrant() []byte {
	return []byte(`{"refresh_token":"canary-other-refresh","client_id":"` + gmailtest.Client + `","client_secret":"` + gmailtest.Secret + `"}`)
}

func noRecord(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(dir, giveFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the record of grants owed a give-back stays: %v", err)
	}
}

func told(h *MailHost, text string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.ContainsFunc(h.notices, func(n notice) bool { return n.text == text })
}

// A crash between a removal and the give-back of the held grant (#3028,
// TN-gmail-socket-b window 1): the next start gives the grant back, so it
// is never left unrevoked and untold.
func TestACrashAfterARemovalGivesTheGrantBackAtStart(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	c := signInConfig(srv)
	h := NewMailHost(context.Background(), dir, sec, c)
	h.mu.Lock()
	prev, err := readMail(dir)
	if err == nil {
		_, err = h.holdGmail(prev)
	}
	if err == nil {
		err = RemoveMail(dir, sec)
	}
	h.mu.Unlock() // the crash: the release never runs
	if err != nil {
		t.Fatal(err)
	}
	if srv.Revokes() != 0 {
		t.Fatalf("revoked %v before the restart", srv.Revoked())
	}
	h2, sec2 := restart(t, dir, c)
	if !slices.Equal(srv.Revoked(), []string{gmailtest.Refresh}) || sec2.Len() != 0 {
		t.Fatalf("after the restart: revoked %v, %d slots; want the held grant given back", srv.Revoked(), sec2.Len())
	}
	if told(h2, noteGmailKept) {
		t.Fatal("a grant Google gave back was told as kept")
	}
	noRecord(t, dir)
}

// A crash after the grant was held but before the change (or after a
// change that failed) keeps the account and its grant at the next start.
func TestACrashBeforeTheChangeKeepsTheAccount(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	srv.Deliver(gmailMail("news@shop.test", "<a@shop.test>"))
	c := signInConfig(srv)
	h := NewMailHost(context.Background(), dir, sec, c)
	h.mu.Lock()
	prev, _ := readMail(dir)
	_, err := h.holdGmail(prev)
	h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := restart(t, dir, c)
	if srv.Revokes() != 0 || h2.cur == nil || h2.why != "" {
		t.Fatalf("revoked %v, read %q; want the account kept and read", srv.Revoked(), h2.why)
	}
	noRecord(t, dir)
}

// A crash after a sign-in put its new grant but before the settings named
// it (#3028, window 2): the next start gives the grant back and drops the
// slot nothing names, so the account before opens again (CLK-1).
func TestACrashBeforeTheSettingsGivesTheNewGrantBack(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	srv.Deliver(gmailMail("news@shop.test", "<a@shop.test>"))
	c := signInConfig(srv)
	h := NewMailHost(context.Background(), dir, sec, c)
	other := GmailSlot("other@gmail.test")
	grant := otherGrant()
	h.mu.Lock()
	err := h.owedNew(other, grant)
	if err == nil {
		err = sec.Put(other, clerk.KindGrant, grant)
	}
	h.mu.Unlock() // the crash: no settings written
	if err != nil {
		t.Fatal(err)
	}
	h2, sec2 := restart(t, dir, c)
	if srv.Revokes() != 1 || sec2.Has(other) || !sec2.Has(GmailSlot(gmailtest.User)) {
		t.Fatalf("revokes %d, other slot %v; want the new grant given back and its slot dropped", srv.Revokes(), sec2.Has(other))
	}
	if h2.why != "" || h2.cur == nil {
		t.Fatalf("the account before does not read: %q", h2.why)
	}
	noRecord(t, dir)
}

// A crash after the settings named the new grant keeps it.
func TestACrashAfterTheSettingsKeepsTheNewGrant(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	c := signInConfig(srv)
	h := NewMailHost(context.Background(), dir, sec, c)
	h.mu.Lock()
	err := h.owedNew(GmailSlot(gmailtest.User), gmailtest.Grant())
	h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	restart(t, dir, c)
	if srv.Revokes() != 0 {
		t.Fatalf("revoked %v; want the named grant kept", srv.Revoked())
	}
	noRecord(t, dir)
}

// A record that does not load is told with the step that ends a kept
// grant, and goes; an entry Google keeps is told the same way.
func TestARecordThatDoesNotLoadIsTold(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	c := signInConfig(srv)
	if err := privfile.WriteAtomic(dir, giveFile, []byte("not sealed"), nil); err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, c)
	if !told(h, noteGmailKept) {
		t.Fatal("a record that does not load was not told")
	}
	noRecord(t, dir)

	// An entry Google keeps.
	h.mu.Lock()
	err := h.owedNew(GmailSlot("other@gmail.test"), gmailtest.Grant())
	h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	srv.Close() // Google does not answer
	h2, _ := restart(t, dir, c)
	if !told(h2, noteGmailKept) {
		t.Fatal("a grant Google kept was not told")
	}
	noRecord(t, dir)
}

// A record that cannot be written makes no change (#3028): removemail and
// setmail answer the error with the Gmail account and its grant in place.
func TestARecordWriteThatFailsChangesNothing(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	c := signInConfig(srv)
	c.giveStop = func(int) bool { return true }
	h := NewMailHost(context.Background(), dir, sec, c)
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	if err := owner.RemoveMail(); err == nil {
		t.Fatal("a removal whose record could not be written passed")
	}
	if !h.still(GmailSlot(gmailtest.User)) || !sec.Has(GmailSlot(gmailtest.User)) || srv.Revokes() != 0 {
		t.Fatalf("after a refused removal: set up %v, revoked %v", h.still(GmailSlot(gmailtest.User)), srv.Revoked())
	}
	imap := MailSettings{Address: "pat@imap.test", IMAP: "imap.example.test:993", SMTP: "smtp.example.test:465"}
	if err := owner.SetMail(imap, "a long enough password"); err == nil {
		t.Fatal("a setup whose record could not be written passed")
	}
	if !h.still(GmailSlot(gmailtest.User)) || sec.Len() != 1 || srv.Revokes() != 0 {
		t.Fatalf("after a refused setup: set up %v, %d slots, revoked %v", h.still(GmailSlot(gmailtest.User)), sec.Len(), srv.Revoked())
	}
}

// With no crash, a removal and a sign-in for another address leave no
// record: every entry is settled in the change's own turn.
func TestAChangeLeavesNoRecord(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	srv.As("other@gmail.test")
	if d := signIn(t, srv, owner, "watch", fakeClient); d == "" || !h.still(GmailSlot("other@gmail.test")) {
		t.Fatalf("a sign-in for another address = %q", d)
	}
	noRecord(t, dir)
	if err := owner.RemoveMail(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(srv.Revoked(), []string{gmailtest.Refresh, gmailtest.Issued(1)}) {
		t.Fatalf("revoked %v", srv.Revoked())
	}
	noRecord(t, dir)
}

// A sign-in whose record cannot be written sets nothing up and gives its
// new grant back, with the account before and its grant in place.
func TestASignInWhoseRecordFailsChangesNothing(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	c := signInConfig(srv)
	c.giveStop = func(int) bool { return true }
	h := NewMailHost(context.Background(), dir, sec, c)
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	srv.As("other@gmail.test")
	if _, err := finishSignIn(t, srv, owner, fakeClient); err == nil {
		t.Fatal("a sign-in whose record could not be written passed")
	}
	if !h.still(GmailSlot(gmailtest.User)) || sec.Len() != 1 || !slices.Equal(srv.Revoked(), []string{gmailtest.Issued(1)}) {
		t.Fatalf("set up %v, %d slots, revoked %v; want the account before kept and the new grant given back", h.still(GmailSlot(gmailtest.User)), sec.Len(), srv.Revoked())
	}
}

// A crash in a real sign-in for another address, after its new grant is put
// and before the settings name it (#3028 window 2, through gmailFinish): the
// next start gives the new grant back, drops its slot and keeps the account
// before. The crash is a panic in setGmail's first step, so none of
// gmailFinish's own clean-up runs.
func TestACrashInASignInGivesTheNewGrantBackAtStart(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	c := signInConfig(srv)
	c.setStop = func(int) bool { panic("crash") }
	h := NewMailHost(context.Background(), dir, sec, c)
	srv.As("other@gmail.test")
	b := h.gmailBegin("watch", fakeClient)
	landing, ok := srv.Approve(b.Consent)
	if b.Detail != "" || !ok {
		t.Fatalf("begin = %+v", b)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the sign-in did not reach the crash")
			}
		}()
		h.gmailFinish("watch", landing)
	}()
	if !sec.Has(GmailSlot("other@gmail.test")) || srv.Revokes() != 0 {
		t.Fatalf("at the crash: new slot %v, revoked %v", sec.Has(GmailSlot("other@gmail.test")), srv.Revoked())
	}
	c.setStop = nil
	h2, sec2 := restart(t, dir, c)
	if !slices.Equal(srv.Revoked(), []string{gmailtest.Issued(1)}) || sec2.Has(GmailSlot("other@gmail.test")) || !sec2.Has(GmailSlot(gmailtest.User)) {
		t.Fatalf("after the restart: revoked %v, slots %v; want the new grant given back and the account before kept", srv.Revoked(), sec2.Names(clerk.MailSlots))
	}
	if !h2.still(GmailSlot(gmailtest.User)) || h2.why != "" {
		t.Fatalf("the account before does not read: %q", h2.why)
	}
	noRecord(t, dir)
}

// A crash inside RemoveMail, after it drops the slots and before it drops
// the settings: the settings still name the account, but its store no
// longer holds the grant, so the start gives the held grant back once.
func TestACrashInsideARemovalGivesTheGrantBack(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	c := signInConfig(srv)
	h := NewMailHost(context.Background(), dir, sec, c)
	h.mu.Lock()
	prev, _ := readMail(dir)
	_, err := h.holdGmail(prev)
	if err == nil {
		err = sec.RemovePrefix(clerk.MailSlots, "") // RemoveMail's first step
	}
	h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	restart(t, dir, c)
	if !slices.Equal(srv.Revoked(), []string{gmailtest.Refresh}) || srv.Revokes() != 1 {
		t.Fatalf("revoked %v in %d calls; want the held grant given back once", srv.Revoked(), srv.Revokes())
	}
	noRecord(t, dir)
}
