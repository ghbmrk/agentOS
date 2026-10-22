package run

// REQ: CLK-1, CH-11, VRB-2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/inbox"
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
	imap    string       // the server's IMAP address, through a forwarder
	dials   atomic.Int64 // connections the clerk made to it
}

// forward relays connections to addr, counting them in n: every sign-in
// attempt, refused or not, is one.
func forward(t *testing.T, addr string, n *atomic.Int64) string {
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
			up, err := net.Dial("tcp", addr)
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
	r.imap = forward(t, r.srv.IMAP, &r.dials)
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	if err := SetMail(dir, sec, MailSettings{Address: imaptest.User, IMAP: r.imap, SMTP: r.srv.SMTP}, password); err != nil {
		t.Fatal(err)
	}
	cfg := mailConfig()
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
	if n := r.asks.Load() - before; n != 1 {
		t.Fatalf("two overlapping re-reads read the mailbox %d times, want once", n)
	}
}

// A re-read that fails keeps the clerk the account last opened, so the
// kernel's steps still reach it, and STATUS says why, in fixed words; the
// next good read clears the line (#2732 item 2).
func TestAFailedReadKeepsTheLastClerk(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
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
	if st, _ := r.owner.Status(); !has(st.Lines, "refused my sign-in") {
		t.Fatalf("status after a refused sign-in: %v", st.Lines)
	}
	dials := r.dials.Load()
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
	r := newHostRig(t, imaptest.Password)
	if m, _ := r.h.clerk(); m == nil {
		t.Fatal("no clerk opened")
	}
	r.h.mu.Lock()
	r.h.refused = true // as a re-read the server refused leaves it
	r.h.mu.Unlock()
	dials := r.dials.Load()
	req := kernel.Request{Plan: kernel.Plan{ID: "p", Steps: []kernel.PlanStep{{Verb: key.Trash, Clerk: "mail"}}}}
	if res := r.h.Do(req, nil); res.Outcome != "failed" || res.Detail != DSignInRefused {
		t.Errorf("a step while the sign-in is refused: %+v", res)
	}
	if got := r.h.Probe(req, nil).Outcome; got != "unknown" {
		t.Errorf("a probe while the sign-in is refused: %q", got)
	}
	if n := r.dials.Load() - dials; n != 0 {
		t.Fatalf("a step or probe signed in %d times while refused", n)
	}
}

// A step whose own sign-in the server refuses fails before any effect, and
// from then on nothing signs in until the owner sets the account up again:
// the step's refusal stops the clerk as a refused read does (#2708 item 2).
func TestAStepsRefusedSignInStopsTheClerk(t *testing.T) {
	srv := imaptest.Start(t)
	srv.Deliver("INBOX", "From: news@shop.test\nTo: "+imaptest.User+"\nSubject: Sale\nMessage-ID: <m1@shop.test>\n\nsynthetic body\n")
	dir := shortDir(t)
	sec, err := OpenSecrets(dir, testSealer())
	if err != nil {
		t.Fatal(err)
	}
	s := MailSettings{Address: imaptest.User, IMAP: srv.IMAP, SMTP: srv.SMTP}
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
	// The password changes at the server's side, as an owner's reset would:
	// the open clerk's next sign-in is refused.
	if err := SetMail(dir, sec, s, "not-the-password-1"); err != nil {
		t.Fatal(err)
	}
	id := b.submitStep(kernel.PlanStep{Verb: key.Organize, Clerk: inbox.Name, Args: map[string]string{"target": ls[0].Mail, "label": "agentOS/bulk"}})
	b.tick(b.now)
	if st := b.step(id); st.Detail != DSignInRefused {
		t.Fatalf("a step whose sign-in was refused: %s %q", st.Phase, st.Detail)
	}
	if st, _ := owner.Status(); !has(st.Lines, "refused my sign-in") {
		t.Fatalf("status after a step's refused sign-in: %v", st.Lines)
	}
	if _, err := planner.Reread(); err == nil || err.Error() != ErrSignInRefused.Error() {
		t.Fatalf("a re-read after a step's refused sign-in: %v", err)
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

// Setup waits for the read in flight before it writes, so a read never mixes
// the old account's files with the new one's.
func TestSetupWaitsForTheReadInFlight(t *testing.T) {
	r := newHostRig(t, imaptest.Password)
	s := MailSettings{Address: imaptest.User, IMAP: r.imap, SMTP: r.srv.SMTP}
	r.hold.Store(true)
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
