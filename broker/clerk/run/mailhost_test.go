package run

// REQ: CLK-1, CH-11, VRB-2

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/imapsmtp/imaptest"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// serveMail serves side of h on a fresh socket for the test's uid.
func serveMail(t *testing.T, h *MailHost, side MailSide) Conn {
	t.Helper()
	sock := filepath.Join(shortDir(t), "m.sock")
	ln, err := ListenMail(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServeMail(ln, h, side)
	return Conn{Socket: sock, UID: os.Getuid(), Timeout: 20 * time.Second}
}

// The owner sets up, replaces and removes the account on the mail process's
// own socket, so the password reaches only that process (CLK-1). A refusal
// keeps its wording and changes nothing; each replacement and removal is
// told once, in the old setup's words (CH-11); and the planner's listing
// follows the account, read again on its request.
func TestMailSetupRunsOnTheClerksOwnSocket(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", mailFrom("news@shop.test", "<n1@shop.test>"))
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, mailConfig())
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	planner := MailPlanner{serveMail(t, h, MailPlannerSide)}

	if _, err := planner.Listing(); err == nil || err.Error() != ErrNoMailAccount.Error() {
		t.Fatalf("a listing with no account: %v", err)
	}
	if res := h.Do(kernel.Request{}, nil); res.Outcome != "failed" || res.Detail != DNoAccount {
		t.Fatalf("a step with no account: %+v", res)
	}
	s := MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}
	bad := s
	bad.Address = "Pat <" + imaptest.User + ">"
	if err := owner.SetMail(bad, imaptest.Password); err == nil || err.Error() != ErrMailAddress.Error() {
		t.Fatalf("a refused setup: %v, want %q", err, ErrMailAddress)
	}
	if err := owner.SetMail(s, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	if ls, err := planner.Listing(); err != nil || len(ls) != 1 {
		t.Fatalf("the listing after setup: %v, %v", ls, err)
	}
	st, err := owner.Status()
	if err != nil || len(st.Notices) != 0 || !has(st.Lines, "I began my record") {
		t.Fatalf("status after the first setup: %+v, %v", st, err)
	}

	if err := owner.SetMail(bad, imaptest.Password); err == nil {
		t.Fatal("a refused replacement was taken")
	}
	if st, _ := owner.Status(); len(st.Notices) != 0 {
		t.Fatalf("a refused replacement was told as one: %+v", st)
	}
	if err := owner.SetMail(s, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	// A notice stays until the owner's side says it was shown: a read, or a
	// lost answer, uses none up.
	st, _ = owner.Status()
	if len(st.Notices) != 1 || st.Notices[0] != noteMailReplaced {
		t.Fatalf("status after a replacement: %+v", st)
	}
	if again, _ := owner.Status(); !slices.Equal(again.Notices, st.Notices) {
		t.Fatalf("reading the notices used them up: %+v", again)
	}
	if err := owner.Told(st.Through); err != nil {
		t.Fatal(err)
	}
	if st, _ := owner.Status(); len(st.Notices) != 0 {
		t.Fatalf("the replacement was told after it was shown: %+v", st)
	}

	srv.Deliver("INBOX", mailFrom("news@shop.test", "<n2@shop.test>"))
	if ls, _ := planner.Listing(); len(ls) != 1 {
		t.Fatalf("the listing changed before a re-read: %d mails", len(ls))
	}
	if ls, err := planner.Reread(); err != nil || len(ls) != 2 {
		t.Fatalf("the re-read: %d mails, %v", len(ls), err)
	}

	if err := owner.RemoveMail(); err != nil {
		t.Fatal(err)
	}
	if st, _ := owner.Status(); len(st.Notices) != 1 || st.Notices[0] != noteMailRemoved || len(st.Lines) != 0 {
		t.Fatalf("status after the removal: %+v", st)
	}
	if _, err := planner.Listing(); err == nil {
		t.Fatal("a listing after the removal")
	}
	if res := h.Do(kernel.Request{}, nil); res.Detail != DNoAccount {
		t.Fatalf("a step after the removal: %+v", res)
	}
}

// Each mail socket serves its side only: the planner cannot set up, remove,
// or read the account or the owner's status, and the owner side's socket has no listing.
func TestEachMailSocketServesOnlyItsSide(t *testing.T) {
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, mailConfig())
	owner := serveMail(t, h, MailOwnerSide)
	planner := serveMail(t, h, MailPlannerSide)
	for _, op := range []string{"setmail", "removemail", "status", "account", "told"} {
		if err := planner.call(op, setMailArgs{Settings: MailSettings{Address: "a@b.test", IMAP: "i.test:993", SMTP: "s.test:465"}, Password: "a-password-12"}, nil); err == nil || !strings.Contains(err.Error(), "no call") {
			t.Fatalf("%s on the planner's socket: %v", op, err)
		}
	}
	for _, op := range []string{"listing", "reread"} {
		if err := owner.call(op, nil, nil); err == nil || !strings.Contains(err.Error(), "no call") {
			t.Fatalf("%s on the owner's socket: %v", op, err)
		}
	}
	if _, err := readMail(dir); !errors.Is(err, ErrNoMailAccount) {
		t.Fatalf("a refused call set up an account (%v)", err)
	}
}

// hostRig is a MailHost over a loopback server with the account set up,
// whose reader can be held mid-read.
type hostRig struct {
	srv     *imaptest.Server
	h       *MailHost
	owner   MailOwner
	planner MailPlanner
	hold    atomic.Bool
	held    chan struct{} // a read reached the reader while held
	release chan struct{}
	asks    atomic.Int64
	imap    string                 // the server's IMAP address, through a forwarder
	dials   atomic.Int64           // connections the clerk made to it
	more    int                    // mails moved delivered
	onDial  atomic.Pointer[func()] // run as each connection is forwarded, before the server answers
	day     atomic.Pointer[string] // the world's Today; nil: today
	to      atomic.Pointer[string] // where connections go instead of srv
	failing string                 // failReads' server that closes each connection; "": none
}

// nextDay moves the world's Today on a day.
func (r *hostRig) nextDay() {
	d := r.h.cfg.World().Today
	t, _ := time.Parse(time.DateOnly, d)
	next := t.AddDate(0, 0, 1).Format(time.DateOnly)
	r.day.Store(&next)
}

// moved delivers another mail, so the next re-read finds the mailbox's Mark
// moved and reads it (#2742 item 1).
func (r *hostRig) moved() {
	r.more++
	r.srv.Deliver("INBOX", mailFrom("deals@shop.test", fmt.Sprintf("<d%d@shop.test>", r.more)))
}

// forward relays connections to addr, counting them in n: every sign-in
// attempt, refused or not, is one.
func forward(t *testing.T, addr string, n *atomic.Int64) string {
	t.Helper()
	return forwardTo(t, func() string { return addr }, n)
}

// forwardTo is forward to whichever server to names at each connection.
func forwardTo(t *testing.T, to func() string, n *atomic.Int64) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			up, err := net.Dial("tcp", to())
			if err != nil {
				c.Close()
				continue
			}
			go func() { io.Copy(up, c); up.Close() }()
			go func() { io.Copy(c, up); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func newHostRig(t *testing.T, password string) *hostRig {
	t.Helper()
	r := &hostRig{srv: imaptest.Start(t), held: make(chan struct{}, 8), release: make(chan struct{})}
	r.srv.Deliver("INBOX", mailFrom("news@shop.test", "<n1@shop.test>"))
	r.imap = forwardTo(t, func() string {
		if f := r.onDial.Load(); f != nil {
			(*f)()
		}
		if a := r.to.Load(); a != nil {
			return *a
		}
		return r.srv.IMAP
	}, &r.dials)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMail(dir, sec, MailSettings{Address: imaptest.User, IMAP: r.imap, SMTP: r.srv.SMTP}, password); err != nil {
		t.Fatal(err)
	}
	cfg := mailConfig()
	cfg.World = func() inbox.World {
		if d := r.day.Load(); d != nil {
			return inbox.World{Today: *d}
		}
		return inbox.World{Today: today}
	}
	cfg.Ask = func(context.Context, string) (string, error) {
		r.asks.Add(1)
		if r.hold.Load() {
			r.held <- struct{}{}
			<-r.release
		}
		return "bulk", nil
	}
	r.h = NewMailHost(context.Background(), dir, sec, cfg)
	r.owner = MailOwner{serveMail(t, r.h, MailOwnerSide)}
	r.planner = MailPlanner{serveMail(t, r.h, MailPlannerSide)}
	return r
}

// A read of the mailbox holds nothing else: while one is in flight, the
// owner's status and the kernel's steps are answered at once, and re-reads
// that overlap it share it (#2732 item 1).
func TestAMailboxReadHoldsUpNothingElse(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	r.moved()
	r.hold.Store(true)
	before := r.asks.Load()
	done := make(chan error, 2)
	go func() { _, err := r.planner.Reread(); done <- err }()
	<-r.held
	go func() { _, err := r.planner.Reread(); done <- err }()
	answered := make(chan struct{})
	go func() {
		r.owner.Status()
		r.h.Do(kernel.Request{}, nil)
		close(answered)
	}()
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("the owner's status or a step waited on the read in flight")
	}
	time.Sleep(100 * time.Millisecond) // the second re-read reaches the read in flight
	r.hold.Store(false)
	close(r.release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if n := r.asks.Load() - before; n != 2 { // one read classes both mails
		t.Fatalf("two overlapping re-reads classed %d mails, want one read's 2", n)
	}
}

// A re-read that fails keeps the clerk the account last opened, so the
// kernel's steps still reach it, and STATUS says why, in fixed words; the
// next good read clears the line (#2732 item 2).
func TestAFailedReadKeepsTheLastClerk(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	r.nextDay() // the re-read reads
	r.srv.FailList("INBOX", true)
	if ls, err := r.planner.Reread(); err != nil || len(ls) != 1 {
		t.Fatalf("a failed re-read: %v, %v; want the last listing", ls, err)
	}
	if res := r.h.Do(kernel.Request{}, nil); res.Detail == DNoAccount {
		t.Fatalf("a step after a failed re-read found no clerk: %+v", res)
	}
	st, _ := r.owner.Status()
	if !has(st.Lines, "I could not read your mailbox: ") || has(st.Lines, "imapsmtp") {
		t.Fatalf("status after a failed re-read: %v", st.Lines)
	}
	r.srv.FailList("INBOX", false)
	if _, err := r.planner.Listing(); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.owner.Status(); has(st.Lines, "could not read your mailbox") {
		t.Fatalf("the line outlived a good read: %v", st.Lines)
	}
}

// When the server refuses the clerk's sign-in, the planner cannot make it
// sign in again: listings and re-reads answer ErrSignInRefused and the
// server sees no further login until the owner sets the account up again
// (#2698 item 5).
func TestARefusedSignInWaitsForTheOwner(t *testing.T) {
	r := newHostRig(t, "not-the-password-1")
	// The side reaches STATUS through the host's path (#2698 items 32, 38).
	if st, _ := r.owner.Status(); !has(st.Lines, "refused my sign-in for reading mail") {
		t.Fatalf("status after a refused sign-in: %v", st.Lines)
	}
	dials := r.dials.Load()
	if dials != 1 {
		t.Fatalf("the refused first read signed in %d times, want once", dials) // the Mark's refusal ends it (#2742 item 1)
	}
	for range 3 {
		if _, err := r.planner.Reread(); err == nil || err.Error() != ErrSignInRefused.Error() {
			t.Fatalf("a re-read after a refused sign-in: %v", err)
		}
		if _, err := r.planner.Listing(); err == nil || err.Error() != ErrSignInRefused.Error() {
			t.Fatalf("a listing after a refused sign-in: %v", err)
		}
	}
	if n := r.dials.Load() - dials; n != 0 {
		t.Fatalf("the planner made the clerk try to sign in %d more times", n)
	}
	if err := r.owner.SetMail(MailSettings{Address: imaptest.User, IMAP: r.imap, SMTP: r.srv.SMTP}, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	if ls, err := r.planner.Listing(); err != nil || len(ls) != 1 {
		t.Fatalf("the listing after setup again: %v, %v", ls, err)
	}
}

// While the server refuses the sign-in, the kernel's steps and probes do
// not sign in either, even with a clerk the account opened before: no plan
// drives failed sign-ins toward a lockout (#2737 combined 4).
func TestARefusedSignInStopsStepsSigningIn(t *testing.T) {
	for stop, detail := range map[error]string{imapsmtp.ErrLoginRefused: DSignInRefused, imapsmtp.ErrNoSignIn: DNoSignIn} {
		r := newHostRig(t, imaptest.Password)
		if m, _ := r.h.clerk(); m == nil {
			t.Fatal("no clerk opened")
		}
		r.h.mu.Lock()
		r.h.stop = stop // as a re-read that failed this way leaves it
		r.h.mu.Unlock()
		dials := r.dials.Load()
		req := kernel.Request{Plan: kernel.Plan{ID: "p", Steps: []kernel.PlanStep{{Verb: key.Trash, Clerk: "mail"}}}}
		if res := r.h.Do(req, nil); res.Outcome != "failed" || res.Detail != detail {
			t.Errorf("a step after %v: %+v", stop, res)
		}
		if got := r.h.Probe(req, nil).Outcome; got != "unknown" {
			t.Errorf("a probe after %v: %q", stop, got)
		}
		if n := r.dials.Load() - dials; n != 0 {
			t.Fatalf("a step or probe signed in %d times after %v", n, stop)
		}
	}
}

// noSignIn serves an IMAP server that offers no sign-in the clerk can make
// (LOGINDISABLED, no AUTH=PLAIN), counting connections in dials.
func noSignIn(t *testing.T, dials *atomic.Int64) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			dials.Add(1)
			go func() {
				defer c.Close()
				io.WriteString(c, "* OK [CAPABILITY IMAP4rev1 LOGINDISABLED] ready\r\n")
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					if tag, cmd, _ := strings.Cut(sc.Text(), " "); strings.EqualFold(cmd, "LOGOUT") {
						io.WriteString(c, "* BYE\r\n"+tag+" OK bye\r\n")
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// A server that offers no sign-in the clerk can make with these settings
// (LOGINDISABLED, no AUTH=PLAIN) stops the clerk as a refusal does: STATUS
// names the reading side and the IMAP settings, never a password, and
// neither re-reads nor listings connect again until setup (#2698 item 32).
func TestAServerWithNoSignInWaitsForTheOwner(t *testing.T) {
	var dials atomic.Int64
	addr := noSignIn(t, &dials)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMail(dir, sec, MailSettings{Address: imaptest.User, IMAP: addr, SMTP: "127.0.0.1:1"}, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	h := NewMailHost(context.Background(), dir, sec, mailConfig())
	owner := MailOwner{serveMail(t, h, MailOwnerSide)}
	planner := MailPlanner{serveMail(t, h, MailPlannerSide)}
	st, _ := owner.Status()
	if !has(st.Lines, "doesn't accept a password sign-in for reading mail") || !has(st.Lines, "IMAP server settings") || has(st.Lines, "password from") || has(st.Lines, "try again") {
		t.Fatalf("status for a server with no sign-in: %v", st.Lines)
	}
	n := dials.Load()
	for range 3 {
		if _, err := planner.Reread(); err == nil || err.Error() != ErrNoPasswordSignIn.Error() {
			t.Fatalf("a re-read: %v", err)
		}
	}
	if got := dials.Load() - n; got != 0 {
		t.Fatalf("%d connections after the server offered no sign-in", got)
	}
}

// A step whose own sign-in the server refuses, or finds no sign-in for,
// fails before any effect, and from then on nothing signs in until the owner
// sets the account up again: the step's failure stops the clerk as a failed
// read does (#2708 item 2, #2698 item 32).
func TestAStepsFailedSignInStopsTheClerk(t *testing.T) {
	for _, c := range []struct {
		name, detail, status string
		planner              error
		// fail makes the open clerk's next sign-in fail that way.
		fail func(t *testing.T, dir string, sec *clerk.Secrets, s MailSettings, to *atomic.Pointer[string], dials *atomic.Int64)
	}{
		{"refused", DSignInRefused, "refused my sign-in", ErrSignInRefused,
			// The password changes at the server's side, as an owner's
			// reset would.
			func(t *testing.T, dir string, sec *clerk.Secrets, s MailSettings, _ *atomic.Pointer[string], _ *atomic.Int64) {
				if err := SetMail(dir, sec, s, "not-the-password-1"); err != nil {
					t.Fatal(err)
				}
			}},
		{"no sign-in", DNoSignIn, "doesn't accept a password sign-in with these settings", ErrNoPasswordSignIn,
			// The provider turns password sign-in off.
			func(t *testing.T, _ string, _ *clerk.Secrets, _ MailSettings, to *atomic.Pointer[string], dials *atomic.Int64) {
				addr := noSignIn(t, dials)
				to.Store(&addr)
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := imaptest.Start(t)
			srv.Deliver("INBOX", "From: news@shop.test\nTo: "+imaptest.User+"\nSubject: Sale\nMessage-ID: <m1@shop.test>\n\nsynthetic body\n")
			dir := shortDir(t)
			sec, err := OpenSecrets(dir, testSealer())
			if err != nil {
				t.Fatal(err)
			}
			var dials atomic.Int64
			var to atomic.Pointer[string]
			to.Store(&srv.IMAP)
			s := MailSettings{Address: imaptest.User, IMAP: forwardTo(t, func() string { return *to.Load() }, &dials), SMTP: srv.SMTP}
			if err := SetMail(dir, sec, s, imaptest.Password); err != nil {
				t.Fatal(err)
			}
			h := NewMailHost(context.Background(), dir, sec, mailConfig())
			owner := MailOwner{serveMail(t, h, MailOwnerSide)}
			planner := MailPlanner{serveMail(t, h, MailPlannerSide)}
			ls, err := planner.Listing()
			if err != nil || len(ls) != 1 {
				t.Fatalf("the listing: %v, %v", ls, err)
			}
			sock := filepath.Join(shortDir(t), "mail.sock")
			ln, err := ListenClerk(sock, os.Getuid())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			go ServeClerk(ln, h, anchors)
			b := newBoxFor(t, sock, inbox.Name, key.Organize)
			c.fail(t, dir, sec, s, &to, &dials)
			id := b.submitStep(kernel.PlanStep{Verb: key.Organize, Clerk: inbox.Name, Args: map[string]string{"target": ls[0].Mail, "label": "agentOS/bulk"}})
			b.tick(b.now)
			if st := b.step(id); st.Detail != c.detail {
				t.Fatalf("a step whose sign-in failed: %s %q", st.Phase, st.Detail)
			}
			if st, _ := owner.Status(); !has(st.Lines, "I stopped working in your mailbox: your mail server "+c.status) {
				t.Fatalf("status after a step's failed sign-in: %v", st.Lines)
			}
			// Nothing signs in again: not a re-read, not the next step (#2742 item 15).
			n := dials.Load()
			if _, err := planner.Reread(); err == nil || err.Error() != c.planner.Error() {
				t.Fatalf("a re-read after a step's failed sign-in: %v", err)
			}
			id = b.submitStep(kernel.PlanStep{Verb: key.Organize, Clerk: inbox.Name, Args: map[string]string{"target": ls[0].Mail, "label": "agentOS/later"}})
			b.tick(b.now)
			if st := b.step(id); st.Detail != c.detail {
				t.Fatalf("the next step after a failed sign-in: %s %q", st.Phase, st.Detail)
			}
			if got := dials.Load(); got != n {
				t.Fatalf("%d sign-ins after the server's sign-in failed", got-n)
			}
		})
	}
}

// The owner's setup page reads whether an account is set up, and its
// settings, never the password; the read uses up no notice (#2732 item 3).
func TestTheOwnerReadsWhetherAnAccountIsSetUp(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	s := MailSettings{Address: imaptest.User, IMAP: r.imap, SMTP: r.srv.SMTP}
	if a, err := r.owner.Account(); err != nil || !a.Set || a.Settings != s {
		t.Fatalf("the account read: %+v, %v", a, err)
	}
	var raw json.RawMessage
	if err := r.owner.call("account", nil, &raw); err != nil || bytes.Contains(raw, []byte(imaptest.Password)) {
		t.Fatalf("the account read carries the password, or failed (%v)", err)
	}
	if err := r.owner.SetMail(s, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	r.owner.Account()
	if err := r.owner.RemoveMail(); err != nil {
		t.Fatal(err)
	}
	if a, err := r.owner.Account(); err != nil || a.Set {
		t.Fatalf("the account read after removal: %+v, %v", a, err)
	}
	st, _ := r.owner.Status()
	if !slices.Equal(st.Notices, []string{noteMailReplaced, noteMailRemoved}) {
		t.Fatalf("notices after account reads: %v", st.Notices)
	}
	// Told drops what was shown, not what came after it.
	if err := r.owner.SetMail(s, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	if err := r.owner.Told(st.Through); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.owner.Status(); len(st.Notices) != 0 {
		t.Fatalf("a setup after a removal is told as a replacement: %v", st.Notices)
	}
	if err := r.owner.SetMail(s, imaptest.Password); err != nil {
		t.Fatal(err)
	}
	st, _ = r.owner.Status()
	if err := r.owner.RemoveMail(); err != nil {
		t.Fatal(err)
	}
	if err := r.owner.Told(st.Through); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.owner.Status(); !slices.Equal(st.Notices, []string{noteMailRemoved}) {
		t.Fatalf("Told dropped a notice that came after the status read: %v", st.Notices)
	}
}

// The owner was shown one account's warm-up end: a change of account while
// Told waits for the read in flight, even to another account and back, began
// that account's record again, and Told does not mark it (#2742 item 14).
// The wait is a bubble's (synctest), so Told is surely waiting when the
// account changes.
func TestToldMarksOnlyTheAccountShown(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	s := MailSettings{Address: imaptest.User, IMAP: r.imap, SMTP: r.srv.SMTP}
	other := s
	other.User = imaptest.User // a sign-in name given: another account's slot
	for _, back := range [][]MailSettings{{other}, {other, s}} {
		synctest.Test(t, func(t *testing.T) {
			if err := SetMail(r.h.dir, r.h.sec, s, imaptest.Password); err != nil {
				t.Fatal(err)
			}
			h := &MailHost{ctx: context.Background(), dir: r.h.dir, sec: r.h.sec, cfg: r.h.cfg}
			h.notify(true, "I have learned when you read mail.")
			done := make(chan struct{})
			h.reading = done // a read in flight
			told := make(chan struct{})
			go func() { h.told(h.seq); close(told) }()
			synctest.Wait() // Told waits for the read
			h.mu.Lock()
			for _, a := range back {
				if err := SetMail(h.dir, h.sec, a, imaptest.Password); err != nil {
					t.Fatal(err)
				}
				h.changed()
			}
			h.notify(true, "the new account's own warm-up end") // a read after setup told it
			last := back[len(back)-1]
			fresh := sealedSeen{Log: inbox.SeenLog{Since: today}}
			if err := saveSeen(h.dir, testSealer(), slotOf(last), fresh); err != nil {
				t.Fatal(err)
			}
			h.reading = nil
			close(done)
			h.mu.Unlock()
			<-told
			if got, ok := loadSeen(h.dir, testSealer(), slotOf(last)); ok != seenLoaded || got.Told {
				t.Fatalf("after %d changes, the account's new record: %v, told %v", len(back), ok, got.Told)
			}
			if !slices.ContainsFunc(h.notices, func(n notice) bool { return n.warm }) {
				t.Fatalf("after %d changes, Told dropped the new account's warm-up end", len(back))
			}
		})
	}
}

// Told covers only the notices the owner side read: a warm-up end that came
// after that read stays to be told, and the record does not keep it as told.
// Two replacements before the owner looks are one notice (#2742 items 16, 17).
func TestToldLeavesTheWarmUpEndItDidNotCover(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	s := MailSettings{Address: imaptest.User, IMAP: r.imap, SMTP: r.srv.SMTP}
	other := s
	other.User = imaptest.User // a sign-in name given: another account's slot
	for range 2 {
		if err := r.owner.SetMail(other, imaptest.Password); err != nil {
			t.Fatal(err)
		}
	}
	st, _ := r.owner.Status()
	if !slices.Equal(st.Notices, []string{noteMailReplaced}) {
		t.Fatalf("after two replacements: %v", st.Notices)
	}
	now, _ := time.Parse(time.DateOnly, today)
	rec := sealedSeen{Log: inbox.SeenLog{Since: now.AddDate(0, 0, -100).Format(time.DateOnly)}}
	if err := saveSeen(r.h.dir, testSealer(), slotOf(other), rec); err != nil {
		t.Fatal(err)
	}
	r.moved()
	if _, err := r.planner.Reread(); err != nil {
		t.Fatal(err)
	}
	if err := r.owner.Told(st.Through); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.owner.Status(); len(st.Notices) != 1 || !strings.HasPrefix(st.Notices[0], "I have learned") {
		t.Fatalf("Told dropped a warm-up end the owner side had not read: %v", st.Notices)
	}
	if got, ok := loadSeen(r.h.dir, testSealer(), slotOf(other)); ok != seenLoaded || got.Told {
		t.Fatalf("the record kept an unread warm-up end as told: %v, %v", ok, got.Told)
	}
}

// Setup waits for the read in flight before it writes, so a read never mixes
// the old account's files with the new one's.
func TestSetupWaitsForTheReadInFlight(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	s := MailSettings{Address: imaptest.User, IMAP: r.imap, SMTP: r.srv.SMTP}
	r.hold.Store(true)
	r.moved()
	go r.planner.Reread()
	<-r.held
	other := s
	other.User = imaptest.User // a sign-in name given: another account's slot
	set := make(chan error, 1)
	go func() { set <- r.owner.SetMail(other, imaptest.Password) }()
	time.Sleep(200 * time.Millisecond)
	if a, err := r.owner.Account(); err != nil || a.Settings != s {
		t.Fatalf("setup wrote while a read was in flight: %+v, %v", a, err)
	}
	r.hold.Store(false)
	close(r.release)
	if err := <-set; err != nil {
		t.Fatal(err)
	}
	if a, _ := r.owner.Account(); a.Settings != other {
		t.Fatalf("after the read, setup did not land: %+v", a)
	}
}

// A removal waits for the read in flight too, so that read cannot write
// the removed account's record of read mail back after it (#2737 combined 1).
func TestRemovalWaitsForTheReadInFlight(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	r.hold.Store(true)
	r.moved()
	go r.planner.Reread()
	<-r.held
	removed := make(chan error, 1)
	go func() { removed <- r.owner.RemoveMail() }()
	time.Sleep(200 * time.Millisecond)
	if a, err := r.owner.Account(); err != nil || !a.Set {
		t.Fatalf("a removal wrote while a read was in flight: %+v, %v", a, err)
	}
	r.hold.Store(false)
	close(r.release)
	if err := <-removed; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(r.h.dir, seenFile)); !os.IsNotExist(err) {
		t.Fatalf("the removed account's record of read mail is on disk: %v", err)
	}
}

// The end of the warm-up is told until the owner's side says it was shown,
// and then never again, across a restart of the clerk's process (#2732
// item 7).
func TestTheWarmUpsEndIsToldUntilShown(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	now, _ := time.Parse(time.DateOnly, today)
	s := MailSettings{Address: imaptest.User, IMAP: r.imap, SMTP: r.srv.SMTP}
	rec := sealedSeen{Log: inbox.SeenLog{Since: now.AddDate(0, 0, -100).Format(time.DateOnly)}}
	if err := saveSeen(r.h.dir, testSealer(), slotOf(s), rec); err != nil {
		t.Fatal(err)
	}
	restart := func() {
		r.h = NewMailHost(context.Background(), r.h.dir, r.h.sec, r.h.cfg)
		r.owner = MailOwner{serveMail(t, r.h, MailOwnerSide)}
	}
	restart()
	st, _ := r.owner.Status()
	if len(st.Notices) != 1 || !strings.HasPrefix(st.Notices[0], "I have learned") {
		t.Fatalf("after the warm-up: %v", st.Notices)
	}
	restart() // not yet shown: told again
	r.planner = MailPlanner{serveMail(t, r.h, MailPlannerSide)}
	st, _ = r.owner.Status()
	if len(st.Notices) != 1 {
		t.Fatalf("an unshown warm-up notice was lost in a restart: %v", st.Notices)
	}
	// A re-read between the owner side's read and its Told tells it anew;
	// shown once, it is not told again (#2737 lens UX 1).
	r.moved()
	if _, err := r.planner.Reread(); err != nil {
		t.Fatal(err)
	}
	if err := r.owner.Told(st.Through); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.owner.Status(); len(st.Notices) != 0 {
		t.Fatalf("a warm-up notice re-read before it was marked shown was told again: %v", st.Notices)
	}
	if err := r.owner.Told(st.Through); err != nil {
		t.Fatal(err)
	}
	restart()
	if st, _ := r.owner.Status(); len(st.Notices) != 0 {
		t.Fatalf("a shown warm-up notice was told again: %v", st.Notices)
	}

	// Nor when the re-read is still in flight as the owner side says it was
	// shown: that read began from the record before it kept the telling.
	if err := saveSeen(r.h.dir, testSealer(), slotOf(s), rec); err != nil {
		t.Fatal(err)
	}
	restart()
	r.planner = MailPlanner{serveMail(t, r.h, MailPlannerSide)}
	st, _ = r.owner.Status()
	r.hold.Store(true)
	r.moved()
	go r.planner.Reread()
	<-r.held
	told := make(chan error, 1)
	go func() { told <- r.owner.Told(st.Through) }()
	time.Sleep(200 * time.Millisecond)
	r.hold.Store(false)
	close(r.release)
	if err := <-told; err != nil {
		t.Fatal(err)
	}
	if st, _ := r.owner.Status(); len(st.Notices) != 0 {
		t.Fatalf("a read in flight as the warm-up's end was shown told it again: %v", st.Notices)
	}

	// An unshown warm-up notice was about the account as it was: a change of
	// account drops it.
	if err := saveSeen(r.h.dir, testSealer(), slotOf(s), rec); err != nil {
		t.Fatal(err)
	}
	restart()
	if err := r.owner.RemoveMail(); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.owner.Status(); !slices.Equal(st.Notices, []string{noteMailRemoved}) {
		t.Fatalf("after a removal, notices %v", st.Notices)
	}
}

// Settings the clerk cannot read are refused in fixed words, not the
// file's own error.
func TestUnreadableSettingsAreToldInFixedWords(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	if err := os.Chmod(filepath.Join(r.h.dir, mailSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.owner.Account(); err == nil || err.Error() != errMailUnreadable.Error() {
		t.Fatalf("an unreadable settings file: %v", err)
	}
}

// After a read fails, the lines of the last read that worked are told as
// that, under the reason, not as news of the failed read (#2742 item 3).
func TestAFailedReadLabelsTheLastGoodReadsLines(t *testing.T) {
	h := &MailHost{why: "I could not read your mailbox: reason. Next.", cur: &Mail{Status: MailStatus{Lines: []string{"old line"}}}}
	if got := h.status().Lines; !slices.Equal(got, []string{h.why, "From my last good read of your mailbox:", "old line"}) {
		t.Fatalf("status after a failed read: %q", got)
	}
	h.why = ""
	if got := h.status().Lines; !slices.Equal(got, []string{"old line"}) {
		t.Fatalf("status after a good read: %q", got)
	}
	// A last good read with no lines gets no label either.
	h.why, h.cur.Status.Lines = "I could not read your mailbox: reason. Next.", nil
	if got := h.status().Lines; !slices.Equal(got, []string{h.why}) {
		t.Fatalf("status after a failed read, no older lines: %q", got)
	}
}

// A re-read on the same day of a mailbox whose Mark has not moved reads
// nothing; new mail reads it again, even mail that arrived during the last
// read, too late for it, since the Mark is taken before the read (#2742
// item 1).
func TestAnUnchangedMailboxIsNotReadAgain(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	before := r.asks.Load()
	for range 3 {
		if ls, err := r.planner.Reread(); err != nil || len(ls) != 1 {
			t.Fatalf("a re-read of an unchanged mailbox: %v, %v", ls, err)
		}
	}
	if n := r.asks.Load() - before; n != 0 {
		t.Fatalf("re-reads of an unchanged mailbox classed %d mails, want none", n)
	}

	r.moved()
	var dials atomic.Int64
	during := func() {
		// Sessions: the change check, the read's Mark, then the read's
		// folders, UIDs and fetch; the mail lands after the UIDs.
		if dials.Add(1) == 5 {
			r.moved()
		}
	}
	r.onDial.Store(&during)
	if _, err := r.planner.Reread(); err != nil {
		t.Fatal(err)
	}
	r.onDial.Store(nil)
	if ls, err := r.planner.Reread(); err != nil || len(ls) != 3 {
		t.Fatalf("mail that arrived during the last read: %v, %v; want it read", ls, err)
	}
}

// No server can make each re-read a full read: one whose Mark cannot be
// compared (here, STATUS gives no UIDNEXT) is read again only on the next
// day, even after new mail (#2742 item 1).
func TestAnUncomparableMarkWaitsForTheNextDay(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	r.srv.NoUIDNext(true)
	r.moved()
	before := r.asks.Load()
	for range 3 {
		if _, err := r.planner.Reread(); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.asks.Load() - before; n != 0 {
		t.Fatalf("re-reads under an uncomparable Mark classed %d mails, want none", n)
	}
	r.nextDay()
	if ls, err := r.planner.Reread(); err != nil || len(ls) != 2 {
		t.Fatalf("the next day's re-read: %v, %v; want the new mail", ls, err)
	}
}

// After a failed read, a re-read reads again once the server answers, even
// with the mailbox unchanged, so the failure's line clears (#2742 item 1).
func TestAServerBackFromAnOutageIsReadAgain(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	r.srv.FailList("INBOX", true)
	r.nextDay()
	if _, err := r.planner.Reread(); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.owner.Status(); !has(st.Lines, "I could not read your mailbox: ") {
		t.Fatalf("status after a failed read: %v", st.Lines)
	}
	r.srv.FailList("INBOX", false)
	if _, err := r.planner.Listing(); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.owner.Status(); has(st.Lines, "could not read your mailbox") {
		t.Fatalf("the line outlived the outage: %v", st.Lines)
	}
}

// A change check whose sign-in the server refuses is the read's own
// failure: no second sign-in follows it, and the host stops signing in
// (#2742 item 1).
func TestARefusedChangeCheckSignsInOnce(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	refusing := refusingIMAP(t)
	r.to.Store(&refusing)
	before := r.dials.Load()
	if _, err := r.planner.Reread(); err == nil || err.Error() != ErrSignInRefused.Error() {
		t.Fatalf("a re-read whose change check is refused: %v, want ErrSignInRefused", err)
	}
	if _, err := r.planner.Reread(); err == nil || err.Error() != ErrSignInRefused.Error() {
		t.Fatalf("the next re-read: %v, want ErrSignInRefused", err)
	}
	if n := r.dials.Load() - before; n != 1 {
		t.Fatalf("a refused change check made %d connections, want 1", n)
	}
}

// refusingIMAP is an IMAP server that refuses every sign-in.
func refusingIMAP(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				io.WriteString(c, "* OK [CAPABILITY IMAP4rev1] ready\r\n")
				rd := bufio.NewReader(c)
				for {
					line, err := rd.ReadString('\n')
					f := strings.Fields(line)
					if err != nil || len(f) < 2 {
						return
					}
					switch strings.ToUpper(f[1]) {
					case "CAPABILITY":
						io.WriteString(c, "* CAPABILITY IMAP4rev1\r\n"+f[0]+" OK done\r\n")
					case "LOGIN":
						io.WriteString(c, f[0]+" NO [AUTHENTICATIONFAILED] no\r\n")
					default:
						io.WriteString(c, "* BYE bye\r\n"+f[0]+" OK done\r\n")
						return
					}
				}
			}()
		}
	}()
	return l.Addr().String()
}

// A read's day is the clock's as well as the world's, so a world whose date
// stands still cannot keep one read for good (#2742 item 1; #2768 review).
func TestTheReadsDayMovesWithTheClock(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := MailConfig{World: func() inbox.World { return inbox.World{Today: "2026-01-02"} }}
		d := c.day()
		time.Sleep(24 * time.Hour)
		if c.day() == d {
			t.Fatalf("a day later on the clock, under the same world date, the day is still %q", d)
		}
	})
}

// A re-read that finds the Mark moved reads under that Mark, without a
// second change check: the change check and the read's own sessions, no
// more (#2742 item 1; #2768 review).
func TestARereadReadsUnderTheMarkItChecked(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	r.moved()
	r.nextDay() // the read takes its own Mark
	before := r.dials.Load()
	if _, err := r.planner.Reread(); err != nil {
		t.Fatal(err)
	}
	read := r.dials.Load() - before
	r.moved() // within the day: the change check's Mark is the read's
	before = r.dials.Load()
	if _, err := r.planner.Reread(); err != nil {
		t.Fatal(err)
	}
	if n := r.dials.Load() - before; n != read {
		t.Fatalf("a re-read after a moved Mark made %d connections; a read taking its own Mark makes %d", n, read)
	}
}

// A failed read keeps its Mark and day, so a server whose Mark cannot be
// compared is not read again within the day after it fails either: each
// re-read is one change check, never a read attempt (#2742 item 1; #2768
// review).
func TestAFailedReadKeepsItsDay(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	r.srv.NoUIDNext(true)
	r.srv.FailList("INBOX", true)
	r.nextDay()
	if _, err := r.planner.Reread(); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.owner.Status(); !has(st.Lines, "I could not read your mailbox: ") {
		t.Fatalf("status after a failed read: %v", st.Lines)
	}
	before := r.dials.Load()
	for range 3 {
		if _, err := r.planner.Reread(); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.dials.Load() - before; n != 3 {
		t.Fatalf("3 re-reads after a failed read under an uncomparable Mark made %d connections, want 3 change checks", n)
	}
}

// Settings that become unreadable after a good read are told at the next
// re-read as the settings' fault, with setup as the step, and the re-read
// makes no connection (#2742 item 1; #2768 review).
func TestUnreadableSettingsAreToldAtTheNextReread(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	if err := os.Chmod(filepath.Join(r.h.dir, mailSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	r.moved()
	before := r.dials.Load()
	if _, err := r.planner.Reread(); err != nil {
		t.Fatal(err)
	}
	if n := r.dials.Load() - before; n != 0 {
		t.Fatalf("a re-read with unreadable settings made %d connections", n)
	}
	want := "I could not read your mailbox: I could not read my own settings for your mail account. Set up the mail account again on my Wi-Fi page."
	if st, _ := r.owner.Status(); !slices.Contains(st.Lines, want) {
		t.Fatalf("status with unreadable settings: %q", st.Lines)
	}
}

// failReads makes every read attempt fail while its Mark still works: from
// the next re-read on, each re-read's first connection (its change check,
// or the read's own Mark on a new day) reaches the server, and every later
// one reaches a server that closes it at once.
func (r *hostRig) failReads(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	dead := ln.Addr().String()
	r.failing = dead
}

// reread is the planner's re-read, with failReads' first connection let
// through.
func (r *hostRig) reread(t *testing.T) {
	t.Helper()
	var n atomic.Int64
	dead := r.failing
	f := func() {
		if dead != "" && n.Add(1) == 2 {
			r.to.Store(&dead)
		}
	}
	r.onDial.Store(&f)
	defer func() { r.onDial.Store(nil); r.to.Store(nil) }()
	if _, err := r.planner.Reread(); err != nil {
		t.Fatal(err)
	}
}

// A read that fails again under the Mark of the read that failed before it
// is not tried again within the day until the Mark moves: each later
// re-read is one change check, never a read attempt, so a server whose Mark
// works but whose read keeps failing cannot make each re-read a full read
// (#2742, #2768 review). The first failure still gets one more try under
// its own Mark, which a passing fault needs.
func TestARepeatedFailureWaitsForTheMarkToMove(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	r.failReads(t)
	r.nextDay()
	r.reread(t)
	if st, _ := r.owner.Status(); !has(st.Lines, "I could not read your mailbox: ") {
		t.Fatalf("status after a failed read: %v", st.Lines)
	}
	before := r.dials.Load()
	r.reread(t)
	if n := r.dials.Load() - before; n < 2 {
		t.Fatalf("the re-read after a first failure made %d connections, want a change check and a read attempt", n)
	}
	before = r.dials.Load()
	for range 3 {
		r.reread(t)
	}
	if n := r.dials.Load() - before; n != 3 {
		t.Fatalf("3 re-reads after a repeated failure under an unchanged Mark made %d connections, want 3 change checks", n)
	}
	if st, _ := r.owner.Status(); !has(st.Lines, "I could not read your mailbox: ") || !has(st.Lines, "I'll try again when your mail changes, or tomorrow.") {
		t.Fatalf("status after a repeated failure: %v", st.Lines)
	}

	// A moved Mark reads again, and a failure under it is a first failure
	// again, with its own one more try.
	r.moved()
	for i := range 2 {
		before = r.dials.Load()
		r.reread(t)
		if n := r.dials.Load() - before; n < 2 {
			t.Fatalf("re-read %d after the Mark moved made %d connections, want a read attempt", i+1, n)
		}
	}

	// The fault passes, but nothing moved: the line stands until the Mark does.
	r.failing = ""
	r.reread(t)
	if st, _ := r.owner.Status(); !has(st.Lines, "I could not read your mailbox: ") {
		t.Fatalf("an unchanged Mark was read again after a repeated failure: %v", st.Lines)
	}
	r.moved()
	r.reread(t)
	if st, _ := r.owner.Status(); has(st.Lines, "could not read your mailbox") {
		t.Fatalf("the line outlived the fault once the Mark moved: %v", st.Lines)
	}
}

// A repeated failure waits for the Mark only within the day: the next day
// reads again, and its first failure gets its own one more try.
func TestARepeatedFailureIsTriedAgainTheNextDay(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	r.failReads(t)
	r.nextDay()
	r.reread(t)
	r.reread(t)
	r.nextDay()
	for i := range 2 {
		before := r.dials.Load()
		r.reread(t)
		if n := r.dials.Load() - before; n < 2 {
			t.Fatalf("re-read %d of the next day made %d connections, want a read attempt", i+1, n)
		}
	}
	before := r.dials.Load()
	r.reread(t)
	if n := r.dials.Load() - before; n != 1 {
		t.Fatalf("the third re-read of the next day made %d connections, want one change check", n)
	}
}
