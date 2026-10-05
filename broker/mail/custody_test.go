package mail_test

import (
	"context"
	"errors"
	"go/parser"
	"go/token"

	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/mail/imapsmtp"
	"github.com/ghbmrk/agentos/broker/mail/mailtest"
)

// REQ: CRED-1

// TestAdapterHoldsNoCredential: package mail (what the broker links)
// opens no connection and imports no mail protocol client; only
// imapsmtp, served by the vault process, does. Its credential comes from
// the vault per connection.
func TestAdapterHoldsNoCredential(t *testing.T) {
	fs := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		pf, err := parser.ParseFile(fs, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range pf.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if p == "net" || p == "net/smtp" || p == "net/http" || p == "crypto/tls" || p == "os/exec" ||
				strings.HasPrefix(p, "github.com/emersion/") || strings.HasSuffix(p, "/imapsmtp") || strings.HasSuffix(p, "/vault") || strings.HasSuffix(p, "/egress") {
				t.Fatalf("%s imports %s", f, p)
			}
		}
	}
	if typ := reflect.TypeOf(mail.Config{}); fieldNamed(typ, "password", "secret", "token", "credential") {
		t.Fatal("mail.Config has a credential field")
	}
}

func fieldNamed(t reflect.Type, words ...string) bool {
	for i := 0; i < t.NumField(); i++ {
		n := strings.ToLower(t.Field(i).Name)
		for _, w := range words {
			if strings.Contains(n, w) {
				return true
			}
		}
	}
	return false
}

// TestCredentialIsFetchedPerConnectionAndNeverEchoed: the backend asks
// the vault for the credential on each connection, supports OAuth
// (XOAUTH2) on IMAP and SMTP, refuses a plain connection off loopback, and
// a refused login's error carries neither the secret nor the server's
// words.
func TestCredentialIsFetchedPerConnectionAndNeverEchoed(t *testing.T) {
	srv := mailtest.Start(t)
	calls := 0
	oauth := func(context.Context) (imapsmtp.Login, error) {
		calls++
		return imapsmtp.Login{User: mailtest.User, Secret: mailtest.Token, OAuth: true}, nil
	}
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain, From: me, Credential: oauth})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Folders(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.Submit(ctx, []string{"sam@example.com"}, []byte("Subject: x\r\n\r\nx\r\n")); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !slices.Equal(srv.Logins(), []string{"XOAUTH2"}) || srv.Submitted()[0].Auth != "XOAUTH2" {
		t.Fatalf("calls %d, logins %v", calls, srv.Logins())
	}
	wrong := "canary-wrong-secret-7f3a"
	bad, _ := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain, From: me,
		Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: mailtest.User, Secret: wrong}, nil
		}})
	_, err1 := bad.Folders(ctx)
	err2 := bad.Submit(ctx, []string{"sam@example.com"}, []byte("x"))
	for _, err := range []error{err1, err2} {
		if err == nil || strings.Contains(err.Error(), wrong) || strings.Contains(err.Error(), "bad credentials") || strings.Contains(err.Error(), "535") {
			t.Fatalf("login error %v", err)
		}
	}
	noVault, _ := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain, From: me,
		Credential: func(context.Context) (imapsmtp.Login, error) { return imapsmtp.Login{}, errors.New("vault locked") }})
	if _, err := noVault.Folders(ctx); err == nil {
		t.Fatal("ran without a credential")
	}
	for _, sec := range []imapsmtp.Security{imapsmtp.Plain} {
		if _, err := imapsmtp.New(imapsmtp.Config{IMAP: "imap.example.com:143", SMTP: srv.SMTP, IMAPSec: sec, SMTPSec: imapsmtp.Plain, From: me, Credential: oauth}); !errors.Is(err, imapsmtp.ErrInsecure) {
			t.Fatalf("plain IMAP off loopback: %v", err)
		}
		if _, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: "smtp.example.com:25", IMAPSec: imapsmtp.Plain, SMTPSec: sec, From: me, Credential: oauth}); !errors.Is(err, imapsmtp.ErrInsecure) {
			t.Fatalf("plain SMTP off loopback: %v", err)
		}
	}
}

// REQ: ADP-10

// TestStoreCarriesOnlyDeclaredRequests: the vault process serves exactly
// these operations, so a credentialed request outside the adapter's
// declaration (expunge, delete a folder, filters, forwarding, settings)
// cannot be made through it.
func TestStoreCarriesOnlyDeclaredRequests(t *testing.T) {
	typ := reflect.TypeOf((*mail.Store)(nil)).Elem()
	var got []string
	for i := 0; i < typ.NumMethod(); i++ {
		got = append(got, typ.Method(i).Name)
	}
	want := []string{"Append", "Ensure", "Fetch", "Find", "Folders", "Move", "SetFlags", "Submit", "UIDs"}
	if !slices.Equal(got, want) {
		t.Fatalf("Store methods %v", got)
	}
	// The executor refuses intents for other accounts and undeclared
	// operations without touching the mailbox.
	x := newH(t, nil)
	id := x.news(1)
	for _, in := range []journal.Intent{
		{ID: "a", Account: "other", Action: mail.OpArchive, Executor: "mail", Params: rec(id)},
		{ID: "b", Account: "mail", Action: "mail.expunge", Executor: "mail", Params: rec(id)},
		{ID: "c", Account: "mail", Action: mail.OpArchive, Executor: "files", Params: rec(id)},
	} {
		if out := x.run(in); out.Result != journal.ResultNotApplied {
			t.Fatalf("%+v ran: %+v", in, out)
		}
	}
	if folder, _, _ := x.srv.Find(id); folder != "INBOX" {
		t.Fatal("a refused intent moved mail")
	}
}

// TestUnknownSecurityIsRefused: a connection security value outside the
// three known ones is refused, never treated as plaintext.
func TestUnknownSecurityIsRefused(t *testing.T) {
	cred := func(context.Context) (imapsmtp.Login, error) { return imapsmtp.Login{}, nil }
	for _, c := range []imapsmtp.Config{
		{IMAP: "imap.example.com:993", SMTP: "smtp.example.com:465", IMAPSec: imapsmtp.Security(7), From: me, Credential: cred},
		{IMAP: "imap.example.com:993", SMTP: "smtp.example.com:465", SMTPSec: imapsmtp.Security(-1), From: me, Credential: cred},
		{IMAP: "imap.example.com:143", SMTP: "smtp.example.com:465", IMAPSec: imapsmtp.StartTLS, From: me, Credential: cred},
	} {
		if _, err := imapsmtp.New(c); err == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
}
