package run

// REQ: CLK-1, CLK-2, STO-2

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// mailRig is the kernel's process (the box) and the mail clerk served on its
// own socket over a loopback IMAP server, with the account set up in the
// clerk's own directory.
type mailRig struct {
	*box
	srv *imaptest.Server
	dir string
	sec *clerk.Secrets
	ids map[string]string // Message-ID to the clerk's mail id
}

func newMailRig(t *testing.T, msgIDs ...string) *mailRig {
	t.Helper()
	srv := imaptest.Start(t)
	for _, id := range msgIDs {
		srv.Deliver("INBOX", "From: news@shop.test\nTo: "+imaptest.User+"\nSubject: Sale\nMessage-ID: "+id+"\n\nsynthetic body\n")
	}
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMail(dir, sec, MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	acct, err := OpenMail(context.Background(), dir, sec, MailConfig{
		Anchors: anchors, HandleSecret: bytes.Repeat([]byte{9}, 16),
		Ask:   func(context.Context, string) (string, error) { return "bulk", nil },
		World: func() inbox.World { return inbox.World{Today: "2026-10-21"} }, RetentionDays: 30,
		plain: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(shortDir(t), "mail.sock")
	ln, err := ListenClerk(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	go ServeClerk(ln, acct, anchors)
	t.Cleanup(func() { ln.Close() })
	r := &mailRig{box: newBoxFor(t, sock, inbox.Name, key.Organize), srv: srv, dir: dir, sec: sec, ids: map[string]string{}}
	ls := acct.Listing()
	if len(ls) != len(msgIDs) {
		t.Fatalf("the clerk read %d mails, want %d", len(ls), len(msgIDs))
	}
	for i, id := range msgIDs { // the server keeps delivery order, and so does the read
		r.ids[id] = ls[i].Mail
	}
	return r
}

// organize submits and runs a step filing the mail id under the bulk label.
func (r *mailRig) organize(id string) kernel.StepState {
	r.t.Helper()
	p := r.submitStep(kernel.PlanStep{Verb: key.Organize, Clerk: inbox.Name, Args: map[string]string{"target": r.ids[id], "label": "agentOS/bulk"}})
	r.tick(r.now)
	return r.step(p)
}

// filed reports whether the server holds the clerk's keyword on mail id.
func (r *mailRig) filed(id string) bool {
	_, flags, _ := r.srv.Find(id)
	return slices.ContainsFunc(flags, func(f string) bool { return strings.EqualFold(f, "agentOS/bulk") })
}

// The mail clerk's process signs in with the password sealed in its own
// Secrets file, opened inside broker/clerk, and a step the kernel dispatched
// lands on the server. The password is in neither the clerk's files nor the
// kernel's log (#2655).
func TestMailClerkSignsInWithTheSealedPassword(t *testing.T) {
	r := newMailRig(t, "<m1@shop.test>")
	if st := r.organize("<m1@shop.test>"); st.Phase != kernel.PDone || !r.filed("<m1@shop.test>") {
		t.Fatalf("organize: step %+v, filed %v; want done and filed", st, r.filed("<m1@shop.test>"))
	}
	for _, f := range []string{filepath.Join(r.dir, secretsName), filepath.Join(r.dir, mailSettings), r.cfg.Log} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(imaptest.Password)) {
			t.Fatalf("%s holds the password in the clear", filepath.Base(f))
		}
	}
	// A restarted clerk process loads the same sealed slot.
	if _, err := OpenSecrets(r.dir, testSealer()); err != nil {
		t.Fatal(err)
	}
}

// A removed or replaced password takes effect at the next connection: the
// clerk serving the account keeps running, and nothing lands until the right
// password is set again.
func TestMailRemovalTakesEffectAtTheNextConnection(t *testing.T) {
	r := newMailRig(t, "<m1@shop.test>", "<m2@shop.test>", "<m3@shop.test>")
	if err := RemoveMail(r.dir, r.sec); err != nil {
		t.Fatal(err)
	}
	if st := r.organize("<m1@shop.test>"); st.Phase == kernel.PDone || r.filed("<m1@shop.test>") {
		t.Fatalf("after removal: step %+v, filed %v; want not done", st, r.filed("<m1@shop.test>"))
	}
	if _, err := os.Stat(filepath.Join(r.dir, mailSettings)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("removal left the settings")
	}
	if _, err := OpenMail(context.Background(), r.dir, r.sec, MailConfig{plain: true}); !errors.Is(err, ErrNoMailAccount) {
		t.Fatalf("OpenMail after removal: %v, want ErrNoMailAccount", err)
	}

	set := MailSettings{Address: imaptest.User, IMAP: r.srv.IMAP, SMTP: r.srv.SMTP}
	if err := SetMail(r.dir, r.sec, set, "canary-wrong-password"); err != nil {
		t.Fatal(err)
	}
	if st := r.organize("<m2@shop.test>"); st.Phase == kernel.PDone || r.filed("<m2@shop.test>") {
		t.Fatalf("wrong password: step %+v, filed %v; want not done", st, r.filed("<m2@shop.test>"))
	}
	if err := SetMail(r.dir, r.sec, set, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	if st := r.organize("<m3@shop.test>"); st.Phase != kernel.PDone || !r.filed("<m3@shop.test>") {
		t.Fatalf("password set again: step %+v, filed %v; want done", st, r.filed("<m3@shop.test>"))
	}
}

// Each setup refusal keeps the old setup's fixed wording, names no value, and
// writes nothing.
func TestMailSetupRefusalsKeepTheirWording(t *testing.T) {
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	ok := MailSettings{Address: "you@example.com", IMAP: "imap.example.com:993", SMTP: "smtp.example.com:465"}
	pass := "canary-good-password"
	with := func(f func(*MailSettings)) MailSettings { s := ok; f(&s); return s }
	for _, c := range []struct {
		s    MailSettings
		pass string
		want string
	}{
		{with(func(s *MailSettings) { s.Address = "You <you@example.com>" }), pass, "Enter the mailbox's own address, like you@example.com, with no name around it."},
		{with(func(s *MailSettings) { s.IMAP = "imap.example.com" }), pass, "Enter each server as name:port, like imap.example.com:993 and smtp.example.com:465, from your provider's settings page."},
		{with(func(s *MailSettings) { s.SMTP = "smtp.example.com:0" }), pass, "Enter each server as name:port, like imap.example.com:993 and smtp.example.com:465, from your provider's settings page."},
		{with(func(s *MailSettings) { s.User = "you\nroot" }), pass, "Enter the sign-in name on one line, or leave it empty to sign in with the address."},
		{ok, "short", "Paste the mailbox password or app password from your provider, 12 to 256 characters on one line."},
		{ok, "canary-two\nlines-pass", "Paste the mailbox password or app password from your provider, 12 to 256 characters on one line."},
	} {
		err := SetMail(dir, sec, c.s, c.pass)
		if err == nil || err.Error() != c.want {
			t.Errorf("SetMail(%+v): %v, want %q", c.s, err, c.want)
		}
	}
	if sec.Len() != 0 {
		t.Fatal("a refused setup sealed a password")
	}
	if es, _ := os.ReadDir(dir); len(es) != 0 {
		t.Fatalf("a refused setup wrote %d files", len(es))
	}
}
