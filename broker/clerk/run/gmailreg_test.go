package run

// REQ: TN-gmail-registration-a, TN-gmail-registration-b, TN-gmail-registration-c, CLK-1 (TN-gmail-registration-f1)

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

// A Gmail account set up signs in again with its own registration, not the
// kept one: the consent address offers the account's address first (#3065).
func TestAnAccountSetUpBeatsTheKeptRegistration(t *testing.T) {
	_, dir, _, owner := signedInHost(t)
	if _, ok := loadReg(dir, testSealer()); !ok {
		t.Fatal("no kept registration after the sign-in")
	}
	consent, d, err := owner.GmailBegin("watch", nil)
	if err != nil || d != "" {
		t.Fatalf("GmailBegin = %q, %v", d, err)
	}
	if u, _ := url.Parse(consent); u.Query().Get("login_hint") != gmailtest.User {
		t.Fatalf("consent address %s is not a sign-in again", consent)
	}
}

// A registration that fails to be kept leaves the account set up, and
// GmailFinish says the write failed (#3065).
func TestAFailedRegistrationWriteIsReported(t *testing.T) {
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	// A directory holding a file: no rename replaces it.
	if err := os.MkdirAll(filepath.Join(dir, regFile, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	owner := MailOwner{serveMail(t, NewMailHost(context.Background(), dir, sec, signInConfig(srv)), MailOwnerSide)}
	if _, err := finishSignIn(t, srv, owner, fakeClient); err == nil {
		t.Fatal("GmailFinish reports no error for a registration it did not keep")
	}
	if a, err := owner.Account(); err != nil || a.Settings != (MailSettings{Address: gmailtest.User, API: APIGmail}) {
		t.Fatalf("Account = %+v, %v; want the Gmail account set up", a, err)
	}
	if !sec.Has(GmailSlot(gmailtest.User)) {
		t.Fatal("the Gmail grant is not sealed")
	}
}

// A kept registration that is not the clerk's own private file, or holds no
// ID or no secret though sealed as a registration, counts as missing (#3065).
func TestAnUnfitRegistrationCountsAsMissing(t *testing.T) {
	for name, spoil := range map[string]func(t *testing.T, path string){
		"open to others": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, path string) {
			if err := os.Rename(path, path+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(path)+".real", path); err != nil {
				t.Fatal(err)
			}
		},
		"no secret": func(t *testing.T, path string) { sealReg(t, path, `{"id":"x","secret":""}`) },
		"no id":     func(t *testing.T, path string) { sealReg(t, path, `{"id":"","secret":"y"}`) },
	} {
		t.Run(name, func(t *testing.T) {
			_, dir, _, owner := signedInHost(t)
			if err := owner.RemoveMail(); err != nil {
				t.Fatal(err)
			}
			spoil(t, filepath.Join(dir, regFile))
			if _, d, err := owner.GmailBegin("watch", nil); err != nil || d != clerk.DNoAccount {
				t.Fatalf("GmailBegin = %q, %v; want %q", d, err, clerk.DNoAccount)
			}
		})
	}
}

// sealReg replaces path with plain sealed as a registration.
func sealReg(t *testing.T, path, plain string) {
	t.Helper()
	blob, err := testSealer().Seal([]byte(plain), regAAD())
	if err != nil {
		t.Fatal(err)
	}
	if err := privfile.WriteAtomic(filepath.Dir(path), filepath.Base(path), blob, nil); err != nil {
		t.Fatal(err)
	}
}
