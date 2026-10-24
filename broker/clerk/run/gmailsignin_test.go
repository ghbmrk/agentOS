package run

// REQ: CLK-9, CLK-1, CLK-4

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// signInConfig is gmailConfig with the fake's consent page and revocation
// endpoint.
func signInConfig(srv *gmailtest.Server) MailConfig {
	c := gmailConfig(srv)
	c.gmail.consent, c.gmail.revoke = srv.Consent(), srv.Revoke()
	return c
}

var fakeClient = &clerk.Registration{ID: gmailtest.Client, Secret: gmailtest.Secret}

// signIn runs the owner's sign-in for use over the owner's socket, with
// reg, and returns Finish's detail.
func signIn(t *testing.T, srv *gmailtest.Server, owner MailOwner, use string, reg *clerk.Registration) string {
	t.Helper()
	consent, detail, err := owner.GmailBegin(use, reg)
	if err != nil || detail != "" {
		t.Fatalf("GmailBegin = %q, %v", detail, err)
	}
	landing, ok := srv.Approve(consent)
	if !ok {
		t.Fatalf("the fake refused the consent address %s", consent)
	}
	detail, err = owner.GmailFinish(use, landing)
	if err != nil {
		t.Fatal(err)
	}
	return detail
}

// noFileHolds fails if any file in dir holds one of the canaries in the clear.
func noFileHolds(t *testing.T, dir string, canaries ...string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		for _, c := range canaries {
			if bytes.Contains(b, []byte(c)) {
				t.Fatalf("%s holds a canary in the clear", e.Name())
			}
		}
	}
}

// The owner's socket runs a first Gmail sign-in end to end (#3009): the
// consent address comes out, the paste goes in, and the account Google's
// profile names is set up with its grant sealed in its own slot, the
// registration sealed with it, and nothing secret in a file in the clear.
func TestTheOwnerSignsInToGmailOverTheMailSocket(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	srv.Deliver(gmailMail("news@shop.test", "<a@shop.test>"))
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	if d := signIn(t, srv, owner, "watch", fakeClient); d != clerk.DSignedIn+" watch" {
		t.Fatalf("GmailFinish = %q", d)
	}
	a, err := owner.Account()
	if err != nil || !a.Set || a.Settings != (MailSettings{Address: gmailtest.User, API: APIGmail}) {
		t.Fatalf("Account = %+v, %v", a, err)
	}
	if sec.Len() != 1 || !sec.Has(GmailSlot(gmailtest.User)) {
		t.Fatalf("%d slots after the sign-in; want the Gmail grant only", sec.Len())
	}
	if ls, err := h.listing(false); err != nil || len(ls) != 1 {
		t.Fatalf("listing = %v, %v", ls, err)
	}
	noFileHolds(t, dir, gmailtest.Refresh, gmailtest.Secret)
}

// Begin answers a typed detail, with no value, for a sign-in that cannot
// start, and Finish for a paste with no sign-in waiting (CLK-4).
func TestGmailSignInDetails(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	for _, c := range []struct {
		use  string
		reg  *clerk.Registration
		want string
	}{
		{"watch", nil, clerk.DNoAccount}, // no Gmail account to sign in again with
		{"delete", fakeClient, clerk.DUndeclared},
		{"watch", &clerk.Registration{ID: gmailtest.Client, Secret: "a\nb"}, clerk.DRegistered},
	} {
		if consent, d, err := owner.GmailBegin(c.use, c.reg); err != nil || d != c.want || consent != "" {
			t.Fatalf("GmailBegin(%q) = %q, %q, %v; want %q", c.use, consent, d, err, c.want)
		}
	}
	if d, err := owner.GmailFinish("watch", "http://127.0.0.1:8521/agentos?state=x&code=y"); err != nil || d != clerk.DNoSignIn {
		t.Fatalf("GmailFinish with none waiting = %q, %v", d, err)
	}
	if d, err := owner.GmailRevoke(); err != nil || d != DNotGmail {
		t.Fatalf("GmailRevoke with no account = %q, %v", d, err)
	}
}

// A sign-in again, with the registration sealed in the account's grant,
// clears the reconnect stop: steps and reads run again, and the account
// keeps its record (#3009, the #3011 UX point).
func TestASignInAgainClearsTheReconnectStop(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	srv.Deliver(gmailMail("news@shop.test", "<a@shop.test>"))
	srv.RefuseGrant()
	h := NewMailHost(context.Background(), dir, sec, signInConfig(srv))
	if res := h.Do(kernel.Request{}, nil); res.Detail != DReconnect {
		t.Fatalf("Do before the sign-in = %+v", res)
	}
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	if d := signIn(t, srv, owner, "sort", nil); d != clerk.DSignedIn+" sort" {
		t.Fatalf("GmailFinish = %q", d)
	}
	if h.stop != nil || h.cur == nil {
		t.Fatalf("after the sign-in: stop %v, clerk %v", h.stop, h.cur)
	}
	if ls, err := h.listing(false); err != nil || len(ls) != 1 {
		t.Fatalf("listing = %v, %v", ls, err)
	}
	st, _ := owner.Status()
	if len(st.Lines) > 0 && strings.Contains(st.Lines[0], "Gmail stopped") || slices.Contains(st.Notices, noteMailReplaced) {
		t.Fatalf("status after a sign-in again = %+v", st)
	}
	if len(srv.Revoked()) != 0 {
		t.Fatalf("a sign-in again revoked %v; the new grant would die with the old", srv.Revoked())
	}
}

// A grant Google's profile names no usable address for is given back, and
// nothing is set up.
func TestAGrantWithNoAddressIsGivenBack(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	srv.Fail("/profile", 500)
	if d := signIn(t, srv, owner, "watch", fakeClient); d != DGmailAddress {
		t.Fatalf("GmailFinish = %q, want %q", d, DGmailAddress)
	}
	if !slices.Contains(srv.Revoked(), gmailtest.Refresh) || sec.Len() != 0 {
		t.Fatalf("revoked %v, %d slots; want the grant given back and none kept", srv.Revoked(), sec.Len())
	}
	if a, _ := owner.Account(); a.Set {
		t.Fatalf("an account was set up: %+v", a)
	}
}

// Replacing or removing a Gmail account gives its grant back to Google
// before its slot is dropped (A22, #3009 issuecomment-6385928167); a setup
// the owner entered wrong is refused before anything is given back.
func TestReplacingOrRemovingGmailRevokesItsGrantFirst(t *testing.T) {
	imap := MailSettings{Address: imaptest.User, IMAP: "imap.example.test:993", SMTP: "smtp.example.test:465"}
	t.Run("replace", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
		if err := owner.SetMail(imap, "short"); err == nil || len(srv.Revoked()) != 0 || !sec.Has(GmailSlot(gmailtest.User)) {
			t.Fatalf("a refused setup = %v; revoked %v", err, srv.Revoked())
		}
		if err := owner.SetMail(imap, imaptest.Password); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(srv.Revoked(), []string{gmailtest.Refresh}) || sec.Has(GmailSlot(gmailtest.User)) {
			t.Fatalf("revoked %v; Gmail slot kept %v", srv.Revoked(), sec.Has(GmailSlot(gmailtest.User)))
		}
		if st, _ := owner.Status(); slices.Contains(st.Notices, noteGmailKept) {
			t.Fatalf("a revoked grant was told as kept: %+v", st)
		}
	})
	t.Run("remove", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
		if err := owner.RemoveMail(); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(srv.Revoked(), []string{gmailtest.Refresh}) || sec.Len() != 0 {
			t.Fatalf("revoked %v, %d slots", srv.Revoked(), sec.Len())
		}
	})
	// Google keeps the grant: the removal goes on, so the owner is never
	// stuck on Google's answer, and the owner is told the step that ends it.
	t.Run("kept", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		c := signInConfig(srv)
		c.gmail.revoke = srv.Base() + "/revoke" // answers 401
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, c), MailOwnerSide)}
		if err := owner.RemoveMail(); err != nil || sec.Len() != 0 {
			t.Fatalf("RemoveMail = %v with %d slots", err, sec.Len())
		}
		st, _ := owner.Status()
		if !slices.Contains(st.Notices, noteGmailKept) || !strings.Contains(noteGmailKept, "myaccount.google.com/permissions") {
			t.Fatalf("notices = %v; want the kept grant told with its step", st.Notices)
		}
	})
}

// gmailrevoke gives the grant back and removes the account; a grant Google
// kept stays sealed with the account, so the owner can try again.
func TestGmailRevokeOverTheOwnerSocket(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
		if d, err := owner.GmailRevoke(); err != nil || d != clerk.DRevoked {
			t.Fatalf("GmailRevoke = %q, %v", d, err)
		}
		if a, _ := owner.Account(); a.Set || sec.Len() != 0 || !slices.Equal(srv.Revoked(), []string{gmailtest.Refresh}) {
			t.Fatalf("account %+v, %d slots, revoked %v", a, sec.Len(), srv.Revoked())
		}
		if st, _ := owner.Status(); !slices.Contains(st.Notices, noteGmailRevoked) {
			t.Fatalf("notices = %v", st.Notices)
		}
	})
	t.Run("kept", func(t *testing.T) {
		srv, dir, sec := newGmailAccount(t)
		c := signInConfig(srv)
		c.gmail.revoke = srv.Base() + "/revoke"
		owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, c), MailOwnerSide)}
		if d, err := owner.GmailRevoke(); err != nil || !strings.HasPrefix(d, clerk.DNoRevoke) {
			t.Fatalf("GmailRevoke = %q, %v", d, err)
		}
		if a, _ := owner.Account(); !a.Set || !sec.Has(GmailSlot(gmailtest.User)) {
			t.Fatalf("a kept grant removed the account: %+v", a)
		}
	})
}

// A sign-in again offers the account's own address first, and if the owner
// sets another account up while on Google's page, that setup stands and
// the late grant is given back.
func TestASignInAgainYieldsToALaterSetup(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	consent, d, err := owner.GmailBegin("watch", nil)
	if err != nil || d != "" || !strings.Contains(consent, "login_hint="+url.QueryEscape(gmailtest.User)) {
		t.Fatalf("GmailBegin = %q, %q, %v; want the account's address as the hint", consent, d, err)
	}
	imap := MailSettings{Address: imaptest.User, IMAP: "imap.example.test:993", SMTP: "smtp.example.test:465"}
	if err := owner.SetMail(imap, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	landing, ok := srv.Approve(consent)
	if !ok {
		t.Fatal("the fake refused the consent address")
	}
	if d, err := owner.GmailFinish("watch", landing); err != nil || d != clerk.DNoSignIn {
		t.Fatalf("GmailFinish after a later setup = %q, %v", d, err)
	}
	if a, _ := owner.Account(); a.Settings != imap || sec.Has(GmailSlot(gmailtest.User)) || len(srv.Revoked()) != 1 {
		t.Fatalf("account %+v, Gmail slot %v, revoked %v; want the IMAP setup kept, the old grant given back and no code redeemed",
			a.Settings, sec.Has(GmailSlot(gmailtest.User)), srv.Revoked())
	}
}
