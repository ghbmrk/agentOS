package run

// REQ: TN-gmail-registration-a, TN-gmail-registration-b, TN-gmail-registration-c, CLK-1

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// signedInHost is a mail host with a Gmail account set up by a first
// sign-in with the fake's registration.
func signedInHost(t *testing.T) (*gmailtest.Server, string, *clerk.Secrets, MailOwner) {
	t.Helper()
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	if d := signIn(t, srv, owner, "watch", fakeClient); d != clerk.DSignedIn+" watch" {
		t.Fatalf("first sign-in = %q", d)
	}
	return srv, dir, sec, owner
}

// Removing the Gmail account, switching to IMAP or disconnecting Gmail keeps
// the household's registration: the next sign-in, given none, asks Google
// for the kept client and sets the account up again (#3055).
func TestARegistrationOutlivesItsAccount(t *testing.T) {
	imap := MailSettings{Address: imaptest.User, IMAP: "imap.example.test:993", SMTP: "smtp.example.test:465"}
	for name, drop := range map[string]func(MailOwner) error{
		"remove": func(o MailOwner) error { return o.RemoveMail() },
		"imap":   func(o MailOwner) error { return o.SetMail(imap, imaptest.Password) },
		"revoke": func(o MailOwner) error {
			d, err := o.GmailRevoke()
			if err == nil && d != clerk.DRevoked {
				t.Fatalf("GmailRevoke = %q", d)
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv, _, sec, owner := signedInHost(t)
			if err := drop(owner); err != nil {
				t.Fatal(err)
			}
			if sec.Has(GmailSlot(gmailtest.User)) {
				t.Fatal("the Gmail grant is still sealed")
			}
			consent, d, err := owner.GmailBegin("watch", nil)
			if err != nil || d != "" {
				t.Fatalf("GmailBegin with the kept registration = %q, %v", d, err)
			}
			if u, _ := url.Parse(consent); u.Query().Get("client_id") != gmailtest.Client {
				t.Fatalf("consent address %s does not carry the kept client", consent)
			}
			landing, ok := srv.Approve(consent)
			if !ok {
				t.Fatal("the fake refused the consent address")
			}
			if d, err := owner.GmailFinish("watch", landing); err != nil || d != clerk.DSignedIn+" watch" {
				t.Fatalf("GmailFinish = %q, %v", d, err)
			}
			if a, err := owner.Account(); err != nil || a.Settings != (MailSettings{Address: gmailtest.User, API: APIGmail}) {
				t.Fatalf("Account = %+v, %v", a, err)
			}
		})
	}
}

// The registration is sealed apart from the account's store, which holds
// the account's grant only (CLK-1), and in no file in the clear. A file
// sealed for another purpose, or tampered with, counts as missing, so the
// owner is asked for the registration again.
func TestTheRegistrationIsSealedApart(t *testing.T) {
	_, dir, sec, owner := signedInHost(t)
	if sec.Len() != 1 || !sec.Has(GmailSlot(gmailtest.User)) {
		t.Fatalf("%d slots after the sign-in; want the Gmail grant only", sec.Len())
	}
	if _, err := os.Stat(filepath.Join(dir, regFile)); err != nil {
		t.Fatalf("no sealed registration: %v", err)
	}
	noFileHolds(t, dir, gmailtest.Secret)
	if err := owner.RemoveMail(); err != nil {
		t.Fatal(err)
	}
	// The record of read mail's seal, under the same sealer, is not a
	// registration's.
	blob, err := testSealer().Seal([]byte(`{"id":"x","secret":"y"}`), seenAAD(""))
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"other seal": blob, "garbage": []byte("not sealed")} {
		if err := privfile.WriteAtomic(dir, regFile, b, nil); err != nil {
			t.Fatal(err)
		}
		if _, d, err := owner.GmailBegin("watch", nil); err != nil || d != clerk.DNoAccount {
			t.Fatalf("%s: GmailBegin = %q, %v; want %q", name, d, err, clerk.DNoAccount)
		}
	}
}

// A sign-in with a new registration replaces the kept one.
func TestANewRegistrationReplacesTheKept(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := saveReg(dir, testSealer(), clerk.Registration{ID: "old-client", Secret: "old-secret"}); err != nil {
		t.Fatal(err)
	}
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	if d := signIn(t, srv, owner, "watch", fakeClient); d != clerk.DSignedIn+" watch" {
		t.Fatalf("GmailFinish = %q", d)
	}
	if r, ok := loadReg(dir, testSealer()); !ok || r != *fakeClient {
		t.Fatalf("kept registration %v, %v; want the new one", r.ID, ok)
	}
}
