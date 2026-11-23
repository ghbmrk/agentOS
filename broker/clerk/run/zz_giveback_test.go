package run

// REQ: CLK-9, CLK-1, A22

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// keptText is whether a notice is one telling of a grant Google kept
// (keptNote's texts).
func keptText(text string) bool { return strings.HasPrefix(text, "I could not give") }

// toldKept is whether h told the owner of a grant Google kept.
func toldKept(h *MailHost) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.ContainsFunc(h.notices, func(n notice) bool { return keptText(n.text) })
}

// keptNotices is h's notices of a grant Google kept.
func keptNotices(h *MailHost) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, n := range h.notices {
		if keptText(n.text) {
			out = append(out, n.text)
		}
	}
	return out
}

// safeFor fails unless every kept notice h told, while setUp is the Gmail
// account set up here, names no step that would end that account's grant
// and says not to remove the app from it (#6633 UX 1).
func safeFor(t *testing.T, h *MailHost, setUp string) {
	t.Helper()
	ns := keptNotices(h)
	if len(ns) == 0 {
		t.Fatal("no kept grant was told")
	}
	for _, n := range ns {
		if strings.Contains(n, "signed in to "+setUp) || strings.Contains(n, "that Gmail account") ||
			!strings.Contains(n, "Do not remove it from "+setUp+", the account set up here") {
			t.Fatalf("a kept notice while %s is set up could end its grant: %q", setUp, n)
		}
	}
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
	if toldKept(h2) {
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
	err := h.owedNew(other, "other@gmail.test", grant)
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
	err := h.owedNew(GmailSlot(gmailtest.User), gmailtest.User, gmailtest.Grant())
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
	if !toldKept(h) {
		t.Fatal("a record that does not load was not told")
	}
	safeFor(t, h, gmailtest.User)
	if ns := keptNotices(h); !strings.Contains(ns[0], "cannot tell which Google account") {
		t.Fatalf("a record that does not load names an account: %q", ns[0])
	}
	noRecord(t, dir)

	// An entry Google keeps.
	h.mu.Lock()
	err := h.owedNew(GmailSlot("other@gmail.test"), "other@gmail.test", gmailtest.Grant())
	h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	srv.Close() // Google does not answer
	h2, _ := restart(t, dir, c)
	if !toldKept(h2) {
		t.Fatal("a grant Google kept was not told")
	}
	safeFor(t, h2, gmailtest.User)
	if ns := keptNotices(h2); !strings.Contains(ns[0], "signed in to other@gmail.test") {
		t.Fatalf("an entry Google kept does not name its account: %q", ns[0])
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

// A sign-in whose record cannot be written gives its new grant back; if
// Google keeps it, the notice names the new account and warns off the one
// set up here (#6633 UX 1, gmailFinish's record failures).
func TestASignInWhoseRecordFailsTellsAKeptGrantSafely(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	c := signInConfig(srv)
	c.giveStop = func(i int) bool { return i == 0 }
	c.gmail.revoke = srv.Base() + "/revoke" // answers 401: Google keeps it
	h := NewMailHost(context.Background(), dir, sec, c)
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	srv.As("other@gmail.test")
	if _, err := finishSignIn(t, srv, owner, fakeClient); err == nil {
		t.Fatal("a sign-in whose record could not be written passed")
	}
	safeFor(t, h, gmailtest.User)
	if ns := keptNotices(h); !strings.Contains(ns[0], "signed in to other@gmail.test") {
		t.Fatalf("the kept new grant's notice does not name its account: %q", ns[0])
	}
}

// With no Gmail account set up, a grant the box cannot name is told as one
// to end in every account signed in with, which ends no account's mail.
func TestAnUnnamedKeptGrantWithNoAccountIsToldEverywhere(t *testing.T) {
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, mailConfig())
	h.mu.Lock()
	got := h.keptNote("")
	named := h.keptNote("pat@gmail.test")
	h.mu.Unlock()
	if got != noteGmailUntold || named != noteGmailKept {
		t.Fatalf("keptNote with no account = %q, %q", got, named)
	}
}

// A kept grant for the account set up here is that account's own second
// sign-in: the notice names no step and warns off removing the app from it
// (#6633 UX 2 point 2).
func TestAKeptGrantForTheSetUpAccountNeedsNoStep(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	h.mu.Lock()
	n := h.keptNote(strings.ToUpper(gmailtest.User))
	h.mu.Unlock()
	if strings.Contains(n, "permissions") || strings.Contains(n, "that Gmail account") || !strings.Contains(n, "needs no step") ||
		!strings.Contains(n, "Do not remove the app you made for agentOS from "+gmailtest.User) {
		t.Fatalf("a kept grant for the set-up account is told %q", n)
	}
}

// A sign-in again whose account changed meanwhile to the grant's own account
// drops the new grant unrevoked, since revoking it would end the set-up
// account's grant; to any other account, it gives the grant back.
func TestASignInAgainOvertakenByItsOwnAccountRevokesNothing(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	for _, own := range []bool{true, false} {
		g, err := h.ownGmailSignIn()
		if err != nil {
			t.Fatal(err)
		}
		if err := g.sec.Put(g.slot, clerk.KindGrant, otherGrant()); err != nil {
			t.Fatal(err)
		}
		g.again, g.addr = true, gmailtest.User
		slot := GmailSlot(gmailtest.User)
		if !own {
			slot = GmailSlot("other@gmail.test")
		}
		before := srv.Revokes()
		h.mu.Lock()
		prev, perr := readMail(dir)
		h.changedMeanwhile(g, slot, prev, perr)
		h.mu.Unlock()
		if got := srv.Revokes() - before; got != map[bool]int{true: 0, false: 1}[own] {
			t.Fatalf("own %v: %d revocations", own, got)
		}
	}
}
