package run

// REQ: CLK-9, CLK-1, VRB-2, STO-2

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// gmailMail is a synthetic mail with CRLF line ends, as Gmail's raw form.
func gmailMail(from, id string) []byte {
	return []byte("From: " + from + "\r\nTo: " + gmailtest.User + "\r\nSubject: Sale\r\nMessage-ID: " + id + "\r\n\r\nsynthetic body\r\n")
}

// gmailConfig is mailConfig over the Gmail fake: its address, its roots and
// its home-network policy.
func gmailConfig(srv *gmailtest.Server) MailConfig {
	c := mailConfig()
	c.plain = false
	c.Guard, c.TLS = srv.Guard(), &tls.Config{RootCAs: srv.Roots()}
	c.gmail.base, c.gmail.token = srv.Base(), srv.Token()
	return c
}

// newGmailAccount is a clerk directory set up with the fake's account, its
// grant sealed where its sign-in would put it.
func newGmailAccount(t *testing.T) (*gmailtest.Server, string, *clerk.Secrets) {
	t.Helper()
	srv := gmailtest.New()
	t.Cleanup(srv.Close)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := sec.Put(GmailSlot(gmailtest.User), clerk.KindGrant, gmailtest.Grant()); err != nil {
		t.Fatal(err)
	}
	if err := SetGmail(dir, sec, gmailtest.User); err != nil {
		t.Fatal(err)
	}
	return srv, dir, sec
}

// A Gmail account's clerk process works through the Gmail API's declared
// calls under its sealed grant (#2925): a step the kernel dispatched lands
// as the agentOS/ label, the grant is in no file in the clear, and the mail
// stays unread.
func TestAGmailAccountIsServedThroughItsSealedGrant(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	gid := srv.Deliver(gmailMail("news@shop.test", "<g1@shop.test>"))
	acct, err := OpenMail(context.Background(), dir, sec, gmailConfig(srv))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(shortDir(t), "mail.sock")
	ln, err := proc.ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	go proc.ServeClerk(ln, acct, anchors)
	t.Cleanup(func() { ln.Close() })
	b := newBoxFor(t, sock, inbox.Name, key.Organize)
	ls := acct.Listing()
	if len(ls) != 1 {
		t.Fatalf("the clerk read %d mails, want 1", len(ls))
	}
	p := b.submitStep(kernel.PlanStep{Verb: key.Organize, Clerk: inbox.Name, Args: map[string]string{"target": ls[0].Mail, "label": "agentOS/bulk"}})
	b.tick(b.now)
	if st := b.step(p); st.Phase != kernel.PDone {
		t.Fatalf("organize: step %+v; want done", st)
	}
	m, _ := srv.Get(gid)
	if !slices.ContainsFunc(m.Labels, func(l string) bool { return srv.LabelName(l) == "agentOS/bulk" }) || !slices.Contains(m.Labels, "UNREAD") {
		t.Fatalf("labels %v; want agentOS/bulk added and the mail still unread", m.Labels)
	}
	for _, f := range []string{filepath.Join(dir, secretsName), filepath.Join(dir, mailSettings), filepath.Join(dir, seenFile), b.cfg.Log} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(gmailtest.Refresh)) || bytes.Contains(raw, []byte("canary-gmailtest-access")) {
			t.Fatalf("%s holds the grant or a token in the clear", filepath.Base(f))
		}
	}
	if got := retention(MailSettings{Address: gmailtest.User, API: APIGmail}, MailConfig{RetentionDays: 3}); got != 30 {
		t.Fatalf("a Gmail account's retention = %d, want Gmail trash's 30", got)
	}
}

// LastOpened for a Gmail account comes from Gmail's read state: a sender
// whose mail the owner read is opened, one whose mail is unread is not, and
// the record keeps the read sender after the owner deletes that mail.
func TestGmailReadStateIsTheClerksLastOpened(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	read := srv.Deliver(gmailMail("News <news@shop.test>", "<r@shop.test>"))
	srv.Open(read)
	srv.Deliver(gmailMail("pat@example.test", "<u@example.test>"))
	c := gmailConfig(srv)
	m, err := OpenMail(context.Background(), dir, sec, c)
	if err != nil {
		t.Fatal(err)
	}
	if lo := m.world().LastOpened; lo["news@shop.test"] != "2026-10-21" || lo["pat@example.test"] != "" {
		t.Fatalf("LastOpened = %v", lo)
	}
	srv.Erase(read)
	m, err = OpenMail(context.Background(), dir, sec, c)
	if err != nil {
		t.Fatal(err)
	}
	if lo := m.world().LastOpened; lo["news@shop.test"] != "2026-10-21" {
		t.Fatalf("after the owner deleted the read mail, LastOpened = %v", lo)
	}
}

// The clerk reads a Gmail account again only when its history id moved:
// nothing changed, no read; a read-state change, a read.
func TestAnUnchangedGmailIsNotReadAgain(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	id := srv.Deliver(gmailMail("news@shop.test", "<a@shop.test>"))
	c := gmailConfig(srv)
	_, mark, err := openMail(context.Background(), dir, sec, c, nil)
	if err != nil || mark == nil {
		t.Fatalf("openMail: mark %v, %v", mark, err)
	}
	if read, _, err := recheck(context.Background(), mark, c.day(), false, dir, sec, c); read || err != nil {
		t.Fatalf("recheck with nothing changed = %v, %v; want no read", read, err)
	}
	srv.Open(id)
	if read, _, err := recheck(context.Background(), mark, c.day(), false, dir, sec, c); !read || err != nil {
		t.Fatalf("recheck after a read-state change = %v, %v; want a read", read, err)
	}
}

// A grant Gmail refuses stops the clerk until the owner signs in again: the
// owner is told in Gmail's reconnect words, the planner gets ErrReconnect,
// and no step or re-read calls the token endpoint again.
func TestARefusedGmailGrantWaitsForTheOwner(t *testing.T) {
	srv, dir, sec := newGmailAccount(t)
	srv.Deliver(gmailMail("news@shop.test", "<a@shop.test>"))
	srv.RefuseGrant()
	h := NewMailHost(context.Background(), dir, sec, gmailConfig(srv))
	st := h.status()
	if len(st.Lines) == 0 || !strings.Contains(st.Lines[0], "Gmail stopped letting me in") || !strings.Contains(st.Lines[0], "sign in again on the owner page") {
		t.Fatalf("status = %+v", st)
	}
	if _, err := h.listing(true); !errors.Is(err, ErrReconnect) {
		t.Fatalf("listing = %v, want ErrReconnect", err)
	}
	if res := h.Do(kernel.Request{}, nil); res.Detail != DReconnect {
		t.Fatalf("Do = %+v, want %q", res, DReconnect)
	}
}

// A Gmail account is set up only with its grant, and takes no servers or
// password; setting it up drops the IMAP account's password it replaces.
func TestGmailSetupNeedsItsGrantAndNoPassword(t *testing.T) {
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetGmail(dir, sec, gmailtest.User); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("SetGmail with no grant = %v, want ErrNoGrant", err)
	}
	if _, err := os.Stat(filepath.Join(dir, mailSettings)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused SetGmail wrote the settings")
	}
	for _, s := range []MailSettings{
		{Address: gmailtest.User, API: APIGmail},
		{Address: gmailtest.User, API: APIGmail, IMAP: "imap.example.test:993"},
		{Address: gmailtest.User, API: "outlook"},
	} {
		if err := SetMail(dir, sec, s, imaptest.Password); !errors.Is(err, ErrMailAPI) {
			t.Fatalf("SetMail(%+v) = %v, want ErrMailAPI", s, err)
		}
	}
	imap := MailSettings{Address: imaptest.User, IMAP: "imap.example.test:993", SMTP: "smtp.example.test:465"}
	if err := SetMail(dir, sec, imap, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	if err := sec.Put(GmailSlot(gmailtest.User), clerk.KindGrant, gmailtest.Grant()); err != nil {
		t.Fatal(err)
	}
	if err := SetGmail(dir, sec, gmailtest.User); err != nil {
		t.Fatal(err)
	}
	if sec.Has(slotOf(imap)) || !sec.Has(GmailSlot(gmailtest.User)) || sec.Len() != 1 {
		t.Fatalf("after the Gmail setup: IMAP slot %v, Gmail slot %v, %d slots", sec.Has(slotOf(imap)), sec.Has(GmailSlot(gmailtest.User)), sec.Len())
	}
	if s, err := readMail(dir); err != nil || s.API != APIGmail || s.IMAP != "" {
		t.Fatalf("settings %+v, %v", s, err)
	}
	if err := RemoveMail(dir, sec); err != nil || sec.Len() != 0 {
		t.Fatalf("RemoveMail = %v with %d slots left; want the grant gone", err, sec.Len())
	}
}
