package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/mail/imapsmtp"
	"github.com/ghbmrk/agentos/broker/mail/mailsock"
	"github.com/ghbmrk/agentos/broker/mail/mailtest"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-1, CRED-7, ADP-2

var mailSet = mailSettings{Address: "owner@example.test", IMAP: "imap.example.test:993", SMTP: "smtp.example.test:465"}

// The mailbox password goes into the vault process at setup and stays
// there: its own entry (CRED-7), never injectable by the proxy, never
// overwritten by the credential path, never in the status the local page
// reads (CRED-1). There is no account until the owner sets one up (W1-d).
func TestTheMailAccountIsSetUpInTheVault(t *testing.T) {
	r := newFastRig(t, true)
	pw := synthetic(t, "canary-mail-")
	if err := r.c.setMail(mailSet, pw); err != errLocked {
		t.Fatalf("set while locked: %v", err)
	}
	if _, err := r.c.mailStatus(); err != errLocked {
		t.Fatalf("status while locked: %v", err)
	}
	r.c.confirm(r.unlock(t), r.code())
	if st, err := r.c.mailStatus(); err != nil || st.Set {
		t.Fatalf("an account before setup: %+v %v", st, err)
	}
	if err := r.c.setMail(mailSet, pw); err != nil {
		t.Fatal(err)
	}
	if s, ok := r.c.v.Secret(mailPasswordName); !ok || s.Reveal() != pw {
		t.Fatal("password not stored as its own entry")
	}
	red, _ := r.c.v.Redactor()
	if got := string(red.Redact([]byte("x " + pw + " y"))); strings.Contains(got, pw) {
		t.Fatal("password not redacted")
	}
	if _, ok := (apiKeysOnly{r.c.v}).Secret(mailPasswordName); ok || hasKind(r.c.v, mailPasswordName, vault.KindAPIKey) {
		t.Fatal("the proxy can inject the mailbox password")
	}
	for _, name := range []string{mailPasswordName, mailSettingsName} {
		if err := r.c.put(name, []byte(synthetic(t, "sk-"))); err != errBadCredential {
			t.Fatalf("credential path wrote %s: %v", name, err)
		}
	}
	st, err := r.c.mailStatus()
	if err != nil || !st.Set || st.Settings != mailSet {
		t.Fatalf("status %+v %v", st, err)
	}
	if b, _ := json.Marshal(st); strings.Contains(string(b), pw) {
		t.Fatal("status carries the password")
	}
	for _, c := range []struct {
		s    mailSettings
		want error
	}{
		{mailSettings{Address: "not an address", IMAP: mailSet.IMAP, SMTP: mailSet.SMTP}, errMailAddress},
		{mailSettings{Address: "Owner <owner@example.test>", IMAP: mailSet.IMAP, SMTP: mailSet.SMTP}, errMailAddress},
		{mailSettings{Address: mailSet.Address, IMAP: "imap.example.test", SMTP: mailSet.SMTP}, errMailServer},
		{mailSettings{Address: mailSet.Address, IMAP: mailSet.IMAP, SMTP: "smtp.example.test:0"}, errMailServer},
		{mailSettings{Address: mailSet.Address, IMAP: "a/b:993", SMTP: mailSet.SMTP}, errMailServer},
		{mailSettings{Address: mailSet.Address, IMAP: mailSet.IMAP, SMTP: mailSet.SMTP, User: "two\nlines"}, errMailUser},
	} {
		if err := r.c.setMail(c.s, pw); err != c.want {
			t.Errorf("%+v: %v", c.s, err)
		}
	}
	for _, p := range []string{"", "short", strings.Repeat("x", 257), "line\nbreak-password"} {
		if err := r.c.setMail(mailSet, p); err != errWeakMailPassword {
			t.Errorf("password %q: %v", p, err)
		}
	}
	if err := r.c.setMail(mailSet, synthetic(t, "canary-mail-")); err != nil {
		t.Fatal(err)
	}
	if err := r.c.removeMail(); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.c.mailStatus(); st.Set {
		t.Fatal("still set after remove")
	}
	if _, ok := r.c.v.Secret(mailPasswordName); ok {
		t.Fatal("password kept after remove")
	}
	if n := len(r.notes); n < 2 || r.notes[n-2] != noteMailReplaced || r.notes[n-1] != noteMailRemoved {
		t.Fatalf("owner told %q", r.notes)
	}
}

// tap is a recording relay in front of mail.sock: every byte either way
// on every connection.
type tap struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (tp *tap) Write(p []byte) (int, error) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.b.Write(p)
}

func (tp *tap) String() string {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.b.String()
}

func (tp *tap) reset() {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.b.Reset()
}

func relay(t *testing.T, to string) (string, *tap) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tap.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	tp := &tap{}
	go func() {
		for {
			in, err := l.Accept()
			if err != nil {
				return
			}
			out, err := net.Dial("unix", to)
			if err != nil {
				in.Close()
				continue
			}
			go func() { io.Copy(io.MultiWriter(out, tp), in); out.(*net.UnixConn).CloseWrite() }()
			go func() { io.Copy(io.MultiWriter(in, tp), out); in.Close(); out.Close() }()
		}
	}()
	return path, tp
}

// mailRig is an open vault serving mail.sock to this uid, with the local
// test server's account set up, mailtest's password as the canary.
func mailRig(t *testing.T) (*fastRig, *mailtest.Server, string) {
	t.Helper()
	r := openRig(t)
	srv := mailtest.Start(t)
	r.c.mailPlain = true
	if err := r.c.setMail(mailSettings{Address: mailtest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}, mailtest.Password); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(t.TempDir(), "run")
	ln, err := serveMail(run, r.c, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return r, srv, filepath.Join(run, mailsock.Socket)
}

func utc(ms []mail.Message) []mail.Message {
	for i := range ms {
		ms[i].Date = ms[i].Date.UTC()
	}
	return ms
}

// TestTheMailboxIsServedOnItsOwnSocket (W1-a): the nine methods through
// mail.sock give what imapsmtp gives directly, and neither the password
// nor the server's own words cross the socket or reach the log.
func TestTheMailboxIsServedOnItsOwnSocket(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	_, srv, sock := mailRig(t)
	path, tp := relay(t, sock)
	c := mailsock.NewClient(path)
	direct, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain,
		From: mailtest.User, Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: mailtest.User, Secret: mailtest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	raw := func(id, subject string) string {
		return "From: Shop <deals@shop.example>\nTo: " + mailtest.User + "\nSubject: " + subject +
			"\nDate: Mon, 05 Oct 2026 08:00:00 +0000\nMessage-ID: " + id + "\nContent-Type: text/plain; charset=utf-8\n\nTwenty percent off boots.\n"
	}
	srv.Deliver("INBOX", raw("<a@shop.example>", "Sale"))
	srv.Deliver("INBOX", raw("<b@shop.example>", "Sale two"), mail.Seen)
	srv.AddFolder("Receipts", "")

	f1, e1 := c.Folders(ctx)
	f2, e2 := direct.Folders(ctx)
	byName := func(a, b mail.Folder) int { return strings.Compare(a.Name, b.Name) }
	slices.SortFunc(f1, byName)
	slices.SortFunc(f2, byName)
	if e1 != nil || e2 != nil || !reflect.DeepEqual(f1, f2) || len(f1) == 0 {
		t.Fatalf("folders: %v %v / %v %v", f1, e1, f2, e2)
	}
	v1, u1, e1 := c.UIDs(ctx, "INBOX")
	v2, u2, e2 := direct.UIDs(ctx, "INBOX")
	if e1 != nil || e2 != nil || v1 != v2 || !reflect.DeepEqual(u1, u2) || len(u1) != 2 {
		t.Fatalf("uids: %v %v %v / %v %v %v", v1, u1, e1, v2, u2, e2)
	}
	m1, e1 := c.Fetch(ctx, "INBOX", v1, u1)
	m2, e2 := direct.Fetch(ctx, "INBOX", v2, u2)
	if e1 != nil || e2 != nil || !reflect.DeepEqual(utc(m1), utc(m2)) || len(m1) != 2 {
		t.Fatalf("fetch: %+v %v / %+v %v", m1, e1, m2, e2)
	}
	m1, e1 = c.Find(ctx, "INBOX", "<b@shop.example>")
	m2, e2 = direct.Find(ctx, "INBOX", "<b@shop.example>")
	if e1 != nil || e2 != nil || !reflect.DeepEqual(utc(m1), utc(m2)) || len(m1) != 1 {
		t.Fatalf("find: %+v %v / %+v %v", m1, e1, m2, e2)
	}
	if _, e1 = c.Fetch(ctx, "INBOX", v1+1, u1); !errors.Is(e1, mail.ErrValidity) {
		t.Fatalf("stale fetch: %v", e1)
	}
	if _, e2 = direct.Fetch(ctx, "INBOX", v1+1, u1); !errors.Is(e2, mail.ErrValidity) {
		t.Fatalf("stale fetch direct: %v", e2)
	}
	ref := m1[0].Ref()
	if err := c.SetFlags(ctx, ref, []string{mail.Flagged}, []string{mail.Seen}); err != nil {
		t.Fatal(err)
	}
	if _, flags, _ := srv.Find("<b@shop.example>"); !reflect.DeepEqual(flags, []string{mail.Flagged}) {
		t.Fatalf("flags %v", flags)
	}
	if err := c.Ensure(ctx, "Archive"); err != nil {
		t.Fatal(err)
	}
	if err := c.Move(ctx, ref, "Archive"); err != nil {
		t.Fatal(err)
	}
	if folder, _, _ := srv.Find("<b@shop.example>"); folder != "Archive" {
		t.Fatalf("moved to %q", folder)
	}
	out := "From: " + mailtest.User + "\r\nTo: friend@example.test\r\nSubject: hi\r\nMessage-ID: <out@example.test>\r\n\r\nhello\r\n"
	if err := c.Append(ctx, "Sent", []string{mail.Seen}, time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC), []byte(out)); err != nil {
		t.Fatal(err)
	}
	if folder, _, ok := srv.Find("<out@example.test>"); !ok || folder != "Sent" {
		t.Fatalf("appended to %q", folder)
	}
	if err := c.Submit(ctx, []string{"friend@example.test"}, []byte(out)); err != nil {
		t.Fatal(err)
	}
	if s := srv.Submitted(); len(s) != 1 || s[0].From != mailtest.User || !reflect.DeepEqual(s[0].Rcpt, []string{"friend@example.test"}) {
		t.Fatalf("submitted %+v", s)
	}
	// Threat check: another sender through the owner's account.
	if err := c.Submit(ctx, []string{"friend@example.test"}, []byte(strings.Replace(out, mailtest.User, "ceo@example.test", 1))); !errors.Is(err, mailsock.ErrRefused) {
		t.Fatalf("forged sender: %v", err)
	}
	if n := len(srv.Submitted()); n != 1 {
		t.Fatalf("%d submitted", n)
	}
	// Threat check: the server's words stay behind.
	srv.FailList("INBOX", true)
	if _, _, err := c.UIDs(ctx, "INBOX"); !errors.Is(err, mailsock.ErrFailed) {
		t.Fatalf("failing list: %v", err)
	}
	if _, _, err := direct.UIDs(ctx, "INBOX"); err == nil || !strings.Contains(err.Error(), "listing failed") {
		t.Fatalf("the server's words: %v", err)
	}
	all := tp.String()
	if all == "" {
		t.Fatal("nothing recorded")
	}
	for _, s := range []string{mailtest.Password, "listing failed"} {
		if strings.Contains(all, s) || strings.Contains(logs.String(), s) {
			t.Fatalf("%q crossed the socket or reached the log", s)
		}
	}
}

// TestTheMailSocketAdmitsOnlyTheBroker: a peer of another uid gets no
// answer.
func TestTheMailSocketAdmitsOnlyTheBroker(t *testing.T) {
	r := openRig(t)
	run := filepath.Join(t.TempDir(), "run")
	ln, err := serveMail(run, r.c, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, err := mailsock.NewClient(filepath.Join(run, mailsock.Socket)).Folders(context.Background()); !errors.Is(err, mailsock.ErrUnreachable) {
		t.Fatalf("another uid: %v", err)
	}
}

// TestNoMailAccountByDefault (W1-d): until the owner sets one up, every
// method answers not connected and the socket says nothing more; while
// the vault is locked, it says locked.
func TestNoMailAccountByDefault(t *testing.T) {
	r := newFastRig(t, true)
	run := filepath.Join(t.TempDir(), "run")
	ln, err := serveMail(run, r.c, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	path, tp := relay(t, filepath.Join(run, mailsock.Socket))
	c := mailsock.NewClient(path)
	ctx := context.Background()
	if _, err := c.Folders(ctx); !errors.Is(err, mailsock.ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
	r.c.confirm(r.unlock(t), r.code())
	if err := r.c.setMail(mailSet, synthetic(t, "canary-mail-")); err != nil {
		t.Fatal(err)
	}
	if err := r.c.removeMail(); err != nil {
		t.Fatal(err)
	}
	tp.reset()
	ref := mail.Ref{Folder: "INBOX", Validity: 1, UID: 1}
	raw := []byte("From: " + mailSet.Address + "\r\nTo: friend@example.test\r\n\r\nhi\r\n")
	_, e1 := c.Folders(ctx)
	_, _, e2 := c.UIDs(ctx, "INBOX")
	_, e3 := c.Fetch(ctx, "INBOX", 1, []uint32{1})
	_, e4 := c.Find(ctx, "INBOX", "<x@example.test>")
	for i, err := range []error{e1, e2, e3, e4, c.SetFlags(ctx, ref, []string{mail.Seen}, nil), c.Move(ctx, ref, "Archive"),
		c.Ensure(ctx, "Archive"), c.Append(ctx, "Sent", nil, time.Now(), raw), c.Submit(ctx, []string{"friend@example.test"}, raw)} {
		if !errors.Is(err, mailsock.ErrNotConnected) {
			t.Errorf("method %d: %v", i, err)
		}
	}
	if got := strings.Count(tp.String(), `{"error":"not_connected"}`+"\n"); got != 9 {
		t.Fatalf("%d not-connected replies in %q", got, tp.String())
	}
}

// TestAStoreHeldAcrossAChangeLogsInAsNoOne: a Store taken from the vault
// before a lock, a removal or a replacement opens no session afterwards;
// the old password is not cached in it, so the server sees no login.
func TestAStoreHeldAcrossAChangeLogsInAsNoOne(t *testing.T) {
	ctx := context.Background()
	must := func(t *testing.T, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, change := range map[string]func(t *testing.T, r *fastRig, srv *mailtest.Server){
		"lock":   func(t *testing.T, r *fastRig, _ *mailtest.Server) { r.c.lock() },
		"remove": func(t *testing.T, r *fastRig, _ *mailtest.Server) { must(t, r.c.removeMail()) },
		"new password": func(t *testing.T, r *fastRig, srv *mailtest.Server) {
			must(t, r.c.setMail(mailSettings{Address: mailtest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}, synthetic(t, "canary-mail-")))
		},
		"new account": func(t *testing.T, r *fastRig, srv *mailtest.Server) {
			must(t, r.c.setMail(mailSettings{Address: "other@example.test", IMAP: srv.IMAP, SMTP: srv.SMTP}, mailtest.Password))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, srv, _ := mailRig(t)
			acct, err := r.c.mailSource()
			if err != nil {
				t.Fatal(err)
			}
			change(t, r, srv)
			if _, err := acct.Store.Folders(ctx); err == nil {
				t.Error("folders listed after the change")
			}
			out := "From: " + mailtest.User + "\r\nTo: friend@example.test\r\nSubject: hi\r\n\r\nhello\r\n"
			if err := acct.Store.Submit(ctx, []string{"friend@example.test"}, []byte(out)); err == nil {
				t.Error("submitted after the change")
			}
			if l, s := srv.Logins(), srv.Submitted(); len(l) != 0 || len(s) != 0 {
				t.Fatalf("logins %v, submitted %d", l, len(s))
			}
		})
	}
}
