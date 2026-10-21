package run

// REQ: CLK-1, CLK-2, STO-2

import (
	"bytes"
	"context"
	"encoding/json"
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

// A replacement moves the account to another server: the clerk opened on the
// old account has no password to send, so the old server sees no login and
// nothing lands there, and the replaced slot is gone from the Secrets file.
// A clerk opened on the new account signs in there (CLK-1, MAIL-gen).
func TestMailReplacementSendsNoPasswordToTheOldServer(t *testing.T) {
	r := newMailRig(t, "<m1@shop.test>", "<m2@shop.test>")
	old := r.srv.Logins()
	srvB := imaptest.Start(t)
	b := MailSettings{Address: imaptest.User, IMAP: srvB.IMAP, SMTP: srvB.SMTP}
	if err := SetMail(r.dir, r.sec, b, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	if st := r.organize("<m1@shop.test>"); st.Phase == kernel.PDone || r.filed("<m1@shop.test>") {
		t.Fatalf("old clerk after replacement: step %+v, filed %v; want not done", st, r.filed("<m1@shop.test>"))
	}
	if n := len(r.srv.Logins()); n != len(old) {
		t.Fatalf("the old server saw %d logins after the replacement, want none", n-len(old))
	}
	if r.sec.Has(slotOf(MailSettings{Address: imaptest.User, IMAP: r.srv.IMAP, SMTP: r.srv.SMTP})) || r.sec.Len() != 1 {
		t.Fatalf("the replaced password is still sealed (%d slots)", r.sec.Len())
	}
	if _, err := OpenMail(context.Background(), r.dir, r.sec, MailConfig{HandleSecret: bytes.Repeat([]byte{9}, 16),
		Ask: func(context.Context, string) (string, error) { return "bulk", nil }, plain: true}); err != nil || len(srvB.Logins()) == 0 {
		t.Fatalf("a clerk opened on the new account: %v, %d logins there", err, len(srvB.Logins()))
	}
}

// SetMail stopped after sealing the new password but before writing the new
// settings, as a crash would: the running clerk still signs in to its own
// account with its own password, not the new one, and a SetMail run again
// completes the replacement.
func TestMailSetupStoppedBetweenItsWritesSendsTheOldPassword(t *testing.T) {
	r := newMailRig(t, "<m1@shop.test>")
	b := MailSettings{Address: imaptest.User, IMAP: "imap.b.test:993", SMTP: "smtp.b.test:465"}
	if err := r.sec.Put(slotOf(b), clerk.KindStatic, []byte("canary-account-B-pass")); err != nil {
		t.Fatal(err)
	}
	if st := r.organize("<m1@shop.test>"); st.Phase != kernel.PDone || !r.filed("<m1@shop.test>") {
		t.Fatalf("after a stopped setup: step %+v, filed %v; want done with the account's own password", st, r.filed("<m1@shop.test>"))
	}
	if err := SetMail(r.dir, r.sec, b, "canary-account-B-pass"); err != nil {
		t.Fatal(err)
	}
	if got, err := readMail(r.dir); err != nil || got != b || r.sec.Len() != 1 {
		t.Fatalf("setup run again: %+v, %v, %d slots", got, err, r.sec.Len())
	}
}

// SetMail stopped after each of its steps, as a crash would, leaves settings
// whose own slot opens to their own password, so a clerk opened on them sends
// it only to their servers; RemoveMail then leaves no mail password sealed,
// a crash-left one included (#2704).
func TestMailSetupStoppedAtEveryStepSendsOnlyItsOwnPassword(t *testing.T) {
	a := MailSettings{Address: "you@example.com", IMAP: "imap.a.test:993", SMTP: "smtp.a.test:465"}
	b := MailSettings{Address: "you@example.com", IMAP: "imap.b.test:993", SMTP: "smtp.b.test:465"}
	pass := map[MailSettings]string{a: "canary-account-A-pass", b: "canary-account-B-pass"}
	for i := 0; i < 3; i++ {
		dir := shortDir(t)
		sec, err := OpenSecrets(dir, testSealer())
		if err != nil {
			t.Fatal(err)
		}
		if err := SetMail(dir, sec, a, pass[a]); err != nil {
			t.Fatal(err)
		}
		if err := setMail(dir, sec, b, pass[b], func(j int) bool { return j == i }); !errors.Is(err, errStopped) {
			t.Fatalf("stop after step %d: %v", i, err)
		}
		sec, err = OpenSecrets(dir, testSealer()) // the restarted clerk process
		if err != nil {
			t.Fatal(err)
		}
		s, err := readMail(dir)
		if err != nil {
			t.Fatal(err)
		}
		l, err := sec.Login(slotOf(s), s.login())(context.Background())
		if err != nil || l.Secret != pass[s] {
			t.Fatalf("stopped after step %d: settings for %s sign in with %q, %v; want their own password", i, s.IMAP, l.Secret, err)
		}
		if err := RemoveMail(dir, sec); err != nil {
			t.Fatal(err)
		}
		if re, err := OpenSecrets(dir, testSealer()); err != nil || re.Len() != 0 {
			t.Fatalf("stopped after step %d, then removed: %d slots still sealed", i, re.Len())
		}
	}
}

// A setup that crashed mid-write leaves temporaries holding the sealed
// password and the settings; RemoveMail leaves neither (#2706 UX 1), whether
// or not the store still holds a mail slot. With none, RemoveMail writes no
// store, so only its own removal clears the torn Secrets temporary.
func TestMailRemovalLeavesNoCrashedTemporary(t *testing.T) {
	for _, held := range []bool{true, false} {
		dir := shortDir(t)
		sec, err := OpenSecrets(dir, testSealer())
		if err != nil {
			t.Fatal(err)
		}
		a := MailSettings{Address: "you@example.com", IMAP: "imap.a.test:993", SMTP: "smtp.a.test:465"}
		if err := SetMail(dir, sec, a, "canary-account-A-pass"); err != nil {
			t.Fatal(err)
		}
		atRest, _ := sec.MarshalBinary()
		if !held {
			if err := sec.RemovePrefix(clerk.MailSlots, ""); err != nil {
				t.Fatal(err)
			}
		}
		b, _ := json.Marshal(a)
		for _, name := range []string{secretsName, mailSettings} {
			body := map[string][]byte{secretsName: atRest, mailSettings: b}[name]
			if err := writeAtomic(dir, name, body, func(i int) bool { return i == 2 }); !errors.Is(err, errStopped) {
				t.Fatal(err)
			}
		}
		if err := RemoveMail(dir, sec); err != nil {
			t.Fatal(err)
		}
		if es, _ := os.ReadDir(dir); len(es) != 1 || es[0].Name() != secretsName {
			var names []string
			for _, e := range es {
				names = append(names, e.Name())
			}
			t.Fatalf("slot held %v: after removal the clerk's directory holds %v, want only the emptied Secrets file", held, names)
		}
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

// The settings file is under the Secrets file's custody: a settings file
// open to other uids, or a symlink in its place, is refused, not read.
func TestMailSettingsFileIsTheClerksOwn(t *testing.T) {
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMail(dir, sec, MailSettings{Address: "you@example.com", IMAP: "imap.example.com:993", SMTP: "smtp.example.com:465"}, "canary-good-password"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, mailSettings)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readMail(dir); err == nil {
		t.Fatal("a settings file open to other uids was read")
	}
	b, _ := os.ReadFile(path)
	other := filepath.Join(shortDir(t), "elsewhere")
	if err := os.WriteFile(other, b, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(path)
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if _, err := readMail(dir); err == nil {
		t.Fatal("a symlinked settings file was read")
	}
}
