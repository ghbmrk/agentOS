package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/mail/imapsmtp"
	"github.com/ghbmrk/agentos/broker/mail/mailsock"
	"github.com/ghbmrk/agentos/broker/mail/mailtest"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: ADP-2, OP-3, CH-11, CH-16, M9, M18, ARC-2

// The mail account behind a test vault socket: the mailtest double, the
// IMAP and SMTP store over it, and mailsock serving it, so the adapter
// agentosd binds reaches the mailbox only through the mail socket, as in
// the box. imapsmtp is linked into this test binary only; the fence in
// broker/daemon holds agentosd's own build.

// vault is the vault process's account source, switchable.
type mailVault struct {
	mu   sync.Mutex
	acct mailsock.Account
	err  error
}

func (v *mailVault) source() (mailsock.Account, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.acct, v.err
}

func (v *mailVault) set(a mailsock.Account, err error) {
	v.mu.Lock()
	v.acct, v.err = a, err
	v.mu.Unlock()
}

// serveMail serves src on a new unix socket and returns its path. The
// directory is short: unix socket paths are bounded.
func serveMail(t *testing.T, src mailsock.Source) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ms")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "m.sock")
	ln, err := net.Listen("unix", p)
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
			go mailsock.ServeConn(c, src)
		}
	}()
	return p
}

// mailBox starts the double and returns it with the account the vault
// serves over it.
func mailBox(t *testing.T) (*mailtest.Server, mailsock.Account) {
	t.Helper()
	srv := mailtest.Start(t)
	st, err := imapsmtp.New(imapsmtp.Config{IMAP: srv.IMAP, SMTP: srv.SMTP, IMAPSec: imapsmtp.Plain, SMTPSec: imapsmtp.Plain,
		From: mailtest.User, Credential: func(context.Context) (imapsmtp.Login, error) {
			return imapsmtp.Login{User: mailtest.User, Secret: mailtest.Password}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	srv.AddFolder("Receipts", "")
	return srv, mailsock.Account{Store: st, Address: mailtest.User}
}

// mailOwner is the owner channel as the gate uses it.
type mailOwner struct {
	mu    sync.Mutex
	reqs  map[string][]owner.Item
	order []string
	now   func() time.Time
}

func (o *mailOwner) Request(items []owner.Item, _ time.Duration) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	id := fmt.Sprintf("R%d", len(o.order)+1)
	o.reqs[id] = append([]owner.Item(nil), items...)
	o.order = append(o.order, id)
	return id, nil
}

func (o *mailOwner) RequestEach(items []owner.Item, _ []time.Duration) ([]string, error) {
	var ids []string
	for _, it := range items {
		id, _ := o.Request([]owner.Item{it}, 0)
		ids = append(ids, id)
	}
	return ids, nil
}

func (o *mailOwner) RequestLocalEach(items []owner.Item, ttls []time.Duration) ([]string, error) {
	return o.RequestEach(items, ttls)
}

func (o *mailOwner) Tier(f owner.Facts) owner.Tier {
	return owner.Classify(f, owner.Limits{AmountLimit: 50000}, o.now())
}
func (o *mailOwner) Active(time.Duration) bool { return true }
func (o *mailOwner) QueueAutoReply(owner.AutoReply) (owner.QueueResult, error) {
	return owner.QueueResult{}, errors.New("no auto-replies here")
}
func (o *mailOwner) DueAutoReplies() []owner.Queued { return nil }
func (o *mailOwner) UndoneAfterRelease(string) bool { return false }
func (o *mailOwner) Inform(string) error            { return nil }
func (o *mailOwner) last() (string, []owner.Item) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.order) == 0 {
		return "", nil
	}
	id := o.order[len(o.order)-1]
	return id, o.reqs[id]
}

// escSpy counts the gate's Escalate calls on the account's verifier.
type escSpy struct {
	*lateMail
	mu sync.Mutex
	n  int
}

func (s *escSpy) Escalate(ctx context.Context, in journal.Intent) (grants.Escalation, error) {
	s.mu.Lock()
	s.n++
	s.mu.Unlock()
	return s.lateMail.Escalate(ctx, in)
}

func (s *escSpy) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

// mailRig is the gate and journal composed as daemon.Run composes them,
// from the daemon.Config that lateMail.wire fills, on one clock. A grant
// through daemon.Run itself needs the box's page and a code from the
// owner's generator; here the owner's YES and the page's confirm are the
// gate's own Decide and ConfirmLocal.
type mailRig struct {
	t    *testing.T
	srv  *mailtest.Server
	acct mailsock.Account
	v    *mailVault
	sock string
	l    *lateMail
	spy  *escSpy
	g    *grants.Gate
	eng  *journal.Engine
	st   *journal.FileStore
	own  *mailOwner
	dir  string

	mu  sync.Mutex
	at  time.Time
	n   int
	inU int // calls of the bound adapter's InUse hook
}

// mailDay is day D of the tests: long before the wall clock, so an
// adapter that read the wall clock instead of daemon.Config.Now would not
// count D's places (W2-c).
var mailDay = time.Date(2025, 3, 3, 9, 0, 0, 0, time.UTC)

func newMailRig(t *testing.T, red journal.Redactor) *mailRig {
	t.Helper()
	r := &mailRig{t: t, at: mailDay, dir: t.TempDir()}
	r.srv, r.acct = mailBox(t)
	r.v = &mailVault{}
	r.v.set(r.acct, nil)
	r.sock = serveMail(t, r.v.source)
	r.l = newLateMail()
	r.l.tune = func(c *mail.Config) {
		in := c.InUse
		if in == nil {
			return
		}
		c.InUse = func(action string, since time.Time) []journal.Use {
			r.mu.Lock()
			r.inU++
			r.mu.Unlock()
			return in(action, since)
		}
	}
	cfg := daemon.Config{Redactor: red}
	r.l.wire(&cfg)
	r.spy = &escSpy{lateMail: r.l}
	cfg.Grants.Verifiers[r.l.account] = r.spy
	// Another account's archives, by a stand-in executor and guard, so
	// the journal holds places that are not the adapter's.
	cfg.Executors[standExec] = standAcct{}
	cfg.Grants.Declared[standExec] = mail.Declared()
	cfg.Grants.Verifiers[standAccount] = standAcct{}
	gcfg := cfg.Grants
	gcfg.LocalUI = true
	gcfg.Now = r.now
	r.g = grants.New(gcfg)
	execs := map[string]journal.Executor{grants.ExecutorName: r.g}
	for k, x := range cfg.Executors {
		execs[k] = x
	}
	var err error
	if r.st, err = journal.OpenFile(filepath.Join(r.dir, "journal.log")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.st.Close() })
	if red == nil {
		t.Fatal("the rig's grants need a journal that reads back")
	}
	if r.eng, err = journal.Open(r.st, r.g, execs, red, journal.WithClock(r.now)); err != nil {
		t.Fatal(err)
	}
	r.own = &mailOwner{reqs: map[string][]owner.Item{}, now: r.now}
	r.g.Attach(r.eng, r.own)
	r.grant(grants.Spec{Account: mailAccount, Executor: mail.Tool, Ops: mail.Declared()})
	return r
}

func identity(s string) string { return s }

func (r *mailRig) now() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.at
}

func (r *mailRig) advance(d time.Duration) {
	r.mu.Lock()
	r.at = r.at.Add(d)
	r.mu.Unlock()
}

func (r *mailRig) hookCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inU
}

// bind binds the wrapper as wireMail's binder does, on the rig's clock.
func (r *mailRig) bind() {
	r.t.Helper()
	c := mailsock.NewClient(r.sock)
	if s := r.l.poll(context.Background(), r.eng, c, c, r.now); s != "mail: connected" {
		r.t.Fatalf("bind: %s", s)
	}
}

func (r *mailRig) submit(in journal.Intent) journal.Status {
	r.t.Helper()
	st, err := r.g.Submit(in)
	if err != nil {
		r.t.Fatal(err)
	}
	if st.State == journal.Pending {
		st, _ = r.g.Authorize(context.Background(), in.ID)
	}
	if st.State == journal.Authorized {
		st, _ = r.g.Dispatch(context.Background(), in.ID)
	}
	return st
}

func (r *mailRig) decideAll(yes bool) {
	r.g.Flush()
	req, items := r.own.last()
	for i, it := range items {
		r.g.Decide(owner.Decision{Request: req, Item: i + 1, Ref: it.Ref, Approved: yes, Why: "owner"})
	}
	r.g.Wait()
}

func (r *mailRig) grant(s grants.Spec) {
	r.t.Helper()
	b, _ := json.Marshal(s)
	var m map[string]any
	json.Unmarshal(b, &m)
	id := fmt.Sprintf("local/grant/%d", len(r.eng.List()))
	st := r.submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount, Action: journal.ActionGrantChange,
		Params: map[string]any{"grant": m}, Executor: grants.ExecutorName})
	if st.State != journal.Pending {
		r.t.Fatalf("grant: %s %q", st.State, st.Permission.Reason)
	}
	r.decideAll(true)
	if err := r.g.ConfirmLocal(id); err != nil {
		r.t.Fatal(err)
	}
	r.g.Wait()
}

// news delivers a synthetic newsletter to the inbox and returns its ID.
func (r *mailRig) news(i int, sender string) string {
	id := fmt.Sprintf("<news-%d@%s>", i, sender)
	r.srv.Deliver("INBOX", "From: Shop <deals@"+sender+">\nTo: "+mailtest.User+"\nSubject: Autumn sale "+fmt.Sprint(i)+
		"\nDate: Mon, 05 Oct 2026 08:00:00 +0000\nMessage-ID: "+id+"\nContent-Type: text/plain; charset=utf-8\n\nTwenty percent off boots.\n")
	return id
}

func (r *mailRig) intent(action, account, record string) journal.Intent {
	r.n++
	return journal.Intent{ID: fmt.Sprintf("agent/%d", r.n), Origin: "guest:agent", Account: account, Action: action,
		Params: map[string]any{mail.ParamRecord: record}, Executor: mail.Tool, Machine: "agent", Label: "private"}
}

func (r *mailRig) archive(record string) (journal.Intent, journal.Status) {
	in := r.intent(mail.OpArchive, mailAccount, record)
	return in, r.submit(in)
}

func (r *mailRig) folder(id string) string {
	f, _, _ := r.srv.Find(id)
	return f
}

// TestMailWrapperRechecksAtDispatch (W2-a): the wrapper is the account's
// escalator, so the gate runs the adapter's guard at authorize and again
// at dispatch (OP-3): a message moved in between is not archived.
func TestMailWrapperRechecksAtDispatch(t *testing.T) {
	r := newMailRig(t, identity)
	r.bind()
	id := r.news(1, "shop.example")
	in := r.intent(mail.OpArchive, mailAccount, id)
	if _, err := r.g.Submit(in); err != nil {
		t.Fatal(err)
	}
	st, _ := r.g.Authorize(context.Background(), in.ID)
	authorized := r.spy.count()
	if st.State != journal.Authorized || authorized == 0 {
		t.Fatalf("authorize: %s %q, %d escalations", st.State, st.Permission.Reason, authorized)
	}
	r.srv.Remove("INBOX", id)
	r.srv.Deliver("Receipts", "From: Shop <deals@shop.example>\nTo: "+mailtest.User+"\nSubject: Autumn sale\nMessage-ID: "+id+"\n\nboots\n")
	st, _ = r.g.Dispatch(context.Background(), in.ID)
	if st.State == journal.Succeeded || r.spy.count() <= authorized {
		t.Fatalf("dispatch: %s %q, %d escalations", st.State, st.Permission.Reason, r.spy.count())
	}
	if f := r.folder(id); f != "Receipts" {
		t.Fatalf("moved to %s", f)
	}
	// Control: an unmoved newsletter is archived through the same path.
	ok := r.news(2, "shop.example")
	if _, st := r.archive(ok); st.State != journal.Succeeded || r.folder(ok) != "Archive" {
		t.Fatalf("control: %s %q in %s", st.State, st.Permission.Reason, r.folder(ok))
	}
}

// TestMailUnboundRefuses (W2-a off, W2-b early): before the vault reports
// an account, the wrapper registered under the account denies at
// authorize (no adapter exists, so no guard and no hook ran), executes
// nothing, reconciles to Unknown and verifies nothing; CH-20's private
// replies go by text. A wrapper cannot bind without the journal. Once
// bound, the hook is the journal's and is asked.
func TestMailUnboundRefuses(t *testing.T) {
	r := newMailRig(t, identity)
	id := r.news(1, "shop.example")
	in, st := r.archive(id)
	if st.State != journal.Denied || r.spy.count() == 0 || r.l.adapter() != nil {
		t.Fatalf("unbound: %s %q, %d escalations", st.State, st.Permission.Reason, r.spy.count())
	}
	if out := r.l.Execute(context.Background(), in, 1); out.Result != journal.ResultNotApplied {
		t.Fatalf("execute: %+v", out)
	}
	if out := r.l.Reconcile(context.Background(), in, 1); out.Result != journal.ResultUnknown {
		t.Fatalf("reconcile: %+v", out)
	}
	if _, err := r.l.Verify(context.Background(), in); err == nil {
		t.Fatal("verified while unbound")
	}
	if a, m := r.l.Main(); a != "" || m != "" {
		t.Fatalf("main %q %q", a, m)
	}
	if f := r.folder(id); f != "INBOX" {
		t.Fatalf("moved to %s", f)
	}
	ev := newEvRig(t, destAddr)
	ev.ev.mail = r.l
	ev.ev.reply("agent", true, "Short reply.", "")
	if len(ev.gate.subs) != 0 || len(ev.texts()) != 1 || ev.texts()[0] != "Short reply." {
		t.Fatalf("CH-20 with no account: %+v %q", ev.gate.subs, ev.texts())
	}
	// The mutant "register the adapter before daemon.Run, with no
	// engine" is refused: no adapter exists before the journal does.
	if err := r.l.bind(nil, r.acct.Store, mailtest.User, r.now); !errors.Is(err, errMailNoJournal) || r.l.adapter() != nil {
		t.Fatalf("bind without the journal: %v", err)
	}
	if r.hookCalls() != 0 {
		t.Fatalf("the hook ran %d times before binding", r.hookCalls())
	}
	r.bind()
	if _, st := r.archive(r.news(2, "shop.example")); st.State != journal.Succeeded || r.hookCalls() == 0 {
		t.Fatalf("bound: %s %q, hook %d", st.State, st.Permission.Reason, r.hookCalls())
	}
}

// The stand-in account: it archives whatever it is asked to and records
// nothing outside the journal.
const (
	standAccount = "mail-b"
	standExec    = "stand"
)

type standAcct struct{}

func (standAcct) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}
func (standAcct) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}
func (standAcct) Verify(_ context.Context, in journal.Intent) (grants.Verified, error) {
	rec, _ := in.Params[mail.ParamRecord].(string)
	return grants.Verified{Item: owner.Item{Object: "a newsletter"}, Record: rec}, nil
}
func (standAcct) Escalate(context.Context, journal.Intent) (grants.Escalation, error) {
	return grants.Escalation{}, nil
}

// TestMailBoundCountsOnlyItsAccount (W2-b account, M18): the organize
// bound counts the journal's places of the adapter's own account. With a
// bound of 2, another account's 2 archives today do not ask this
// account's second, and this account's own 2 ask its third after a
// rebind, when only the journal knows them. Mutants: the hook on the
// other account or on "" (the third is not asked).
func TestMailBoundCountsOnlyItsAccount(t *testing.T) {
	r := newMailRig(t, identity)
	tune := r.l.tune
	r.l.tune = func(c *mail.Config) { c.DailyLimit = 2; tune(c) }
	r.bind()
	r.grant(grants.Spec{Account: standAccount, Executor: standExec, Ops: mail.Declared()})
	for i := 0; i < 2; i++ {
		in := r.intent(mail.OpArchive, standAccount, fmt.Sprintf("<b-%d@x.example>", i))
		in.Executor = standExec
		if st := r.submit(in); st.State != journal.Succeeded {
			t.Fatalf("other account %d: %s %q", i, st.State, st.Permission.Reason)
		}
	}
	for i := 1; i <= 2; i++ {
		if _, st := r.archive(r.news(i, "shop.example")); st.State != journal.Succeeded {
			t.Fatalf("archive %d: %s %q", i, st.State, st.Permission.Reason)
		}
	}
	// A fresh adapter, as after agentosd restarts, keeps no places of
	// its own: the third is asked only if the hook gives the journal's.
	r.l.unbind()
	r.bind()
	if _, st := r.archive(r.news(3, "shop.example")); st.State != journal.Pending {
		t.Fatalf("third: %s %q", st.State, st.Permission.Reason)
	}
}

// TestMailPinSurvivesWhileHeld (W2-b bound, OP-3): the adapter's
// judgement of an intent the journal still holds outlives the day's
// expiry, so a message replaced by another with the same ID after 25
// hours is not acted on, though the guard would pass the new one; a judgement of an intent the journal never held expires.
// Mutants: the hook on "" or another account (the swap is archived), or
// no hook (nothing expires, so the second part is refused).
func TestMailPinSurvivesWhileHeld(t *testing.T) {
	r := newMailRig(t, identity)
	r.bind()
	ctx := context.Background()
	id := r.news(1, "shop.example")
	in := r.intent(mail.OpArchive, mailAccount, id)
	r.g.Submit(in)
	if st, _ := r.g.Authorize(ctx, in.ID); st.State != journal.Authorized {
		t.Fatalf("authorize: %s %q", st.State, st.Permission.Reason)
	}
	r.advance(25 * time.Hour)
	swap := func(id string) {
		r.srv.Remove("INBOX", id)
		// Same sender and ID, new message: only the pin tells them apart.
		r.srv.Deliver("INBOX", "From: Shop <deals@shop.example>\nTo: "+mailtest.User+"\nSubject: Autumn sale again\nMessage-ID: "+id+"\n\nboots\n")
	}
	swap(id)
	if st, _ := r.g.Dispatch(ctx, in.ID); st.State == journal.Succeeded {
		t.Fatalf("held intent's swap archived: %s", st.State)
	}
	if f := r.folder(id); f != "INBOX" {
		t.Fatalf("swapped message moved to %s", f)
	}
	// An intent judged once and never journaled: after a day its
	// judgement is gone, so the same ID submitted later is judged afresh.
	id2 := r.news(2, "shop.example")
	j := journal.Intent{ID: "agent/judged", Origin: "guest:agent", Account: mailAccount, Action: mail.OpArchive,
		Params: map[string]any{mail.ParamRecord: id2}, Executor: mail.Tool, Machine: "agent", Label: "private"}
	if _, err := r.l.Escalate(ctx, j); err != nil {
		t.Fatal(err)
	}
	r.advance(25 * time.Hour)
	r.srv.Remove("INBOX", id2)
	r.news(2, "shop.example")
	if st := r.submit(j); st.State != journal.Succeeded || r.folder(id2) != "Archive" {
		t.Fatalf("expired judgement: %s %q in %s", st.State, st.Permission.Reason, r.folder(id2))
	}
}

// TestMailOneClock (W2-c, M9): the adapter and the journal read
// daemon.Config.Now. The effect's record carries the rig's time, and a
// fresh adapter still counts it 23h59m later. Mutant: the adapter on the
// wall clock, years after mailDay (the place is not counted and the
// second archive runs). The journal's side is daemon/clock_test's.
func TestMailOneClock(t *testing.T) {
	r := newMailRig(t, identity)
	tune := r.l.tune
	r.l.tune = func(c *mail.Config) { c.DailyLimit = 1; tune(c) }
	r.bind()
	in, st := r.archive(r.news(1, "shop.example"))
	if st.State != journal.Succeeded {
		t.Fatalf("first: %s %q", st.State, st.Permission.Reason)
	}
	var at time.Time
	for _, rec := range r.eng.Trail() {
		if rec.ID == in.ID && rec.Type == journal.RecObserved {
			at = rec.At
		}
	}
	if !at.Equal(mailDay) {
		t.Fatalf("observed at %v, want %v", at, mailDay)
	}
	r.advance(23*time.Hour + 59*time.Minute)
	r.l.unbind()
	r.bind()
	if _, st := r.archive(r.news(2, "shop.example")); st.State != journal.Pending {
		t.Fatalf("second within the day: %s %q", st.State, st.Permission.Reason)
	}
}

// TestMailUnreadableJournalAsks (ADP-2): with agentosd's default
// redactor the journal cannot read mail changes back, so no UNDO exists
// and every organize effect is asked, whatever the guard judged. The
// rig's journal reads back (its grants need that); the wrapper is set as
// wire sets it for daemon.Run's default redactor.
func TestMailUnreadableJournalAsks(t *testing.T) {
	redactAll := func(s string) string {
		if s == "" {
			return ""
		}
		return daemon.Redacted
	}
	for _, c := range []struct {
		name string
		red  journal.Redactor
		want bool
	}{{"none", nil, false}, {"daemon default", redactAll, false}, {"identity", identity, true}} {
		if got := evidenceReadable(c.red); got != c.want {
			t.Errorf("%s: readable %v", c.name, got)
		}
	}
	r := newMailRig(t, identity)
	r.l.undoable = false
	r.bind()
	id := r.news(1, "shop.example")
	if _, st := r.archive(id); st.State != journal.Pending || r.folder(id) != "INBOX" {
		t.Fatalf("unreadable: %s %q in %s", st.State, st.Permission.Reason, r.folder(id))
	}
}

// TestMailPollStates (W2-a off, release point 2): the binder's states.
// A locked vault keeps the binding and is retried; no account unbinds;
// each logs one plain line; none panics.
func TestMailPollStates(t *testing.T) {
	r := newMailRig(t, identity)
	ctx := context.Background()
	c := mailsock.NewClient(r.sock)
	poll := func() string { return r.l.poll(ctx, r.eng, c, c, r.now) }
	if s := poll(); s != "mail: connected" || r.l.adapter() == nil {
		t.Fatalf("connect: %s", s)
	}
	a := r.l.adapter()
	if s := poll(); s != "mail: connected" || r.l.adapter() != a {
		t.Fatalf("again: %s (rebound: %v)", s, r.l.adapter() != a)
	}
	r.v.set(mailsock.Account{}, mailsock.ErrLocked)
	if s := poll(); !strings.Contains(s, "the vault is locked") || r.l.adapter() != a {
		t.Fatalf("locked: %s", s)
	}
	r.v.set(r.acct, nil)
	if s := poll(); s != "mail: connected" || r.l.adapter() != a {
		t.Fatalf("unlocked: %s", s)
	}
	r.v.set(mailsock.Account{}, mailsock.ErrNotConnected)
	if s := poll(); !strings.Contains(s, "no mail account is set up") || r.l.adapter() != nil {
		t.Fatalf("removed: %s", s)
	}
	gone := mailsock.NewClient(filepath.Join(t.TempDir(), "none.sock"))
	if s := r.l.poll(ctx, r.eng, gone, gone, r.now); !strings.Contains(s, "did not answer") || r.l.adapter() != nil {
		t.Fatalf("unreachable: %s", s)
	}
	if err := r.l.bind(r.eng, r.acct.Store, "", r.now); err == nil {
		t.Fatal("bound with no address")
	}
}

// TestMailUndoIDs (W2-d id, CH-16): three letters of the owner
// channel's alphabet, naming neither account nor day, and different for
// another key, account or day.
func TestMailUndoIDs(t *testing.T) {
	k := undoSubkey([]byte("canary-values-key-0123456789abcd"))
	id := undoID(k, mailAccount, "2025-03-03")
	if len(id) != 3 || strings.Trim(id, "ABCDEFGHJKLMNPQRSTUVWXYZ") != "" {
		t.Fatalf("id %q", id)
	}
	others := map[string]string{
		"key":     undoID(undoSubkey([]byte("canary-values-key-other")), mailAccount, "2025-03-03"),
		"account": undoID(k, "mail-b", "2025-03-03"),
		"day":     undoID(k, mailAccount, "2025-03-04"),
	}
	for what, o := range others {
		if o == id {
			t.Errorf("same id for another %s", what)
		}
	}
	if undoID(k, mailAccount, "2025-03-03") != id {
		t.Fatal("not stable")
	}
}

// TestMailDigestAndUndo (W2-d, ADP-2, CH-16): a day's organize changes
// give the next day's digest line with its UNDO ID, offered once; after
// agentosd restarts on the same journal and values key, the owner's
// UNDO of that ID through the owner channel restores what is unchanged
// and skips what changed; past the window nothing is restored.
func TestMailDigestAndUndo(t *testing.T) {
	r := newMailRig(t, identity)
	r.bind()
	ctx := context.Background()
	var ids []string
	for i := 1; i <= 3; i++ {
		id := r.news(i, "shop.example")
		if _, st := r.archive(id); st.State != journal.Succeeded {
			t.Fatalf("archive %d: %s %q", i, st.State, st.Permission.Reason)
		}
		ids = append(ids, id)
	}
	learn := t.TempDir()
	key, err := readValuesKey(filepath.Join(learn, "values.key"))
	if err != nil {
		t.Fatal(err)
	}
	days := &mailDays{account: mailAccount, key: undoSubkey(key), loc: time.Local, now: r.now, trail: r.eng.Trail, m: r.l}
	undo := undoID(days.key, mailAccount, mailDay.In(time.Local).Format(dayFormat))

	// The day is offered only once it is over, and once acknowledged
	// it is not offered again, also after a restart.
	store := change.FileStore{Path: filepath.Join(t.TempDir(), "mail-digest.json")}
	src, err := newMailSource(days, store)
	if err != nil {
		t.Fatal(err)
	}
	if snap, _ := src.Peek(ctx); snap != nil {
		t.Fatalf("offered during the day: %q", snap.Lines)
	}
	r.advance(24 * time.Hour)
	snap, err := src.Peek(ctx)
	if err != nil || snap == nil || len(snap.Lines) != 1 || !strings.Contains(snap.Lines[0], "Mail organized: 3") ||
		!strings.Contains(snap.Lines[0], "UNDO "+undo+" until") {
		t.Fatalf("digest: %v %+v", err, snap)
	}
	for _, leak := range []string{"Autumn", "boots", mailtest.User} {
		if strings.Contains(snap.Lines[0], leak) {
			t.Errorf("line names %q: %s", leak, snap.Lines[0])
		}
	}
	if err := src.Ack(ctx, *snap); err != nil {
		t.Fatal(err)
	}
	if again, _ := newMailSource(days, store); again == nil {
		t.Fatal("reload")
	} else if s, _ := again.Peek(ctx); s != nil {
		t.Fatalf("offered after ack: %q", s.Lines)
	}

	// Unbound, nothing is restored and the owner is told why.
	off := &mailDays{account: mailAccount, key: days.key, loc: time.Local, now: r.now, trail: r.eng.Trail, m: newLateMail()}
	if s, ok := off.undo(ctx, undo); !ok || !strings.Contains(s, "not connected") {
		t.Fatalf("unbound undo: %v %q", ok, s)
	}
	if _, ok := days.undo(ctx, "ZZZ"); ok && undo != "ZZZ" {
		t.Fatal("unknown id answered")
	}

	// One archived message changes after the archive.
	r.srv.Remove("Archive", ids[0])
	r.srv.Deliver("Archive", "From: Shop <deals@shop.example>\nTo: "+mailtest.User+"\nSubject: Changed\nMessage-ID: "+ids[0]+"\n\nchanged\n")

	// agentosd restarts on the same journal and values key.
	r.st.Close()
	dctx, cancel := context.WithCancel(ctx)
	l2 := newLateMail()
	cfg := daemon.Config{
		JournalPath: filepath.Join(r.dir, "journal.log"), SocketDir: filepath.Join(r.dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(r.dir, "owner.json"), Redactor: identity, Now: r.now,
	}
	l2.wire(&cfg)
	d, err := daemon.Run(dctx, cfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer d.Wait()
	defer cancel()
	wireMail(dctx, l2, d, r.sock, learn, nil, "", r.now)
	for i := 0; l2.adapter() == nil; i++ {
		if i > 200 {
			t.Fatal("not bound after restart")
		}
		time.Sleep(10 * time.Millisecond)
	}
	got := strings.Join(d.Owner().Handle(ctx, ownerNum, "UNDO "+undo), "\n")
	if !strings.Contains(got, "Restored 2; 1 skipped (changed since).") {
		t.Fatalf("UNDO after restart: %q", got)
	}
	for i, id := range ids {
		if f := r.folder(id); (i == 0) != (f == "Archive") {
			t.Errorf("message %d in %s", i+1, f)
		}
	}
	r.advance(7*24*time.Hour + time.Minute)
	if got := strings.Join(d.Owner().Handle(ctx, ownerNum, "UNDO "+undo), "\n"); !strings.Contains(got, "past its undo window") {
		t.Fatalf("UNDO past the window: %q", got)
	}
}
