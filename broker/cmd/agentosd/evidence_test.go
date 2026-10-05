package main

// REQ: CH-20, CH-19, CH-10, CAP-3

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/owner"
)

const destAddr = "owner@example.test"

// fakeEvidenceGate is the gate as the router and the setting use it. Each
// delivery ends in the next of states (then state); a destination change
// that runs is applied.
type fakeEvidenceGate struct {
	mu         sync.Mutex
	addr, acct string
	state      journal.State
	states     []journal.State
	reason     string
	subs       []journal.Intent
}

func (f *fakeEvidenceGate) Evidence() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addr, f.acct
}

func (f *fakeEvidenceGate) Submit(in journal.Intent) (journal.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs = append(f.subs, in)
	return journal.Status{Intent: in, State: journal.Pending}, nil
}

func (f *fakeEvidenceGate) end() journal.State {
	if len(f.states) > 0 {
		s := f.states[0]
		f.states = f.states[1:]
		return s
	}
	return f.state
}

func (f *fakeEvidenceGate) Authorize(_ context.Context, id string) (journal.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	in := f.subs[len(f.subs)-1]
	s := f.end()
	switch s {
	case journal.Denied:
		return journal.Status{Intent: in, State: s, Permission: journal.Permission{Reason: f.reason}}, nil
	case journal.Pending:
		return journal.Status{Intent: in, State: s}, nil
	}
	f.states = append([]journal.State{s}, f.states...)
	return journal.Status{Intent: in, State: journal.Authorized}, nil
}

func (f *fakeEvidenceGate) Dispatch(_ context.Context, id string) (journal.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	in := f.subs[len(f.subs)-1]
	s := f.end()
	if s == journal.Succeeded && in.Action == journal.ActionEvidence {
		f.addr, _ = in.Params[grants.ParamEvidenceAddress].(string)
		f.acct, _ = in.Params[grants.ParamEvidenceAccount].(string)
	}
	return journal.Status{Intent: in, State: s}, nil
}

func (f *fakeEvidenceGate) deliveries() []journal.Intent {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []journal.Intent
	for _, in := range f.subs {
		if in.Action == opDeliver {
			out = append(out, in)
		}
	}
	return out
}

type fakeMailbox struct{}

func (fakeMailbox) Owns(a string) (string, bool) {
	return "mail", a == destAddr || a == "alias@example.test"
}
func (fakeMailbox) Main() (string, string) { return destAddr, "mail" }

type evRig struct {
	gate  *fakeEvidenceGate
	mu    sync.Mutex
	sent  []string
	slept []time.Duration
	ev    *evidence
	now   time.Time
	store *change.MemStore
}

func newEvRig(t *testing.T, addr string) *evRig {
	r := &evRig{gate: &fakeEvidenceGate{addr: addr, acct: "mail", state: journal.Succeeded},
		now: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC), store: &change.MemStore{}}
	if addr == "" {
		r.gate.acct = ""
	}
	r.ev = &evidence{
		notify: func(s string) error { r.mu.Lock(); r.sent = append(r.sent, s); r.mu.Unlock(); return nil },
		mail:   fakeMailbox{},
		kept:   &keptReplies{store: r.store, now: func() time.Time { return r.now }},
		now:    func() time.Time { return r.now },
		sleep:  func(d time.Duration) { r.slept = append(r.slept, d) },
		logf:   t.Logf,
	}
	r.ev.gate.Store(&evidenceGateBox{r.gate})
	return r
}

func (r *evRig) texts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.sent)
}

const longReply = "Your landlord agreed to fix the boiler on Thursday. " +
	"He also mentioned the rent review: the new figure is in the attached letter, along with the clause about pets and the parking space."

const pointer = "Full reply sent to o***@example.test."

// TestPrivateRepliesGoToTheDestination: with a destination set and mail
// connected, a reply from a private machine is delivered there by the
// broker and the text carries only a summary and a pointer (CH-20); a
// public machine's reply, a reply with no destination, and any reply
// while no mail account is connected are texted as before (DEP-3, UX U1).
func TestPrivateRepliesGoToTheDestination(t *testing.T) {
	r := newEvRig(t, destAddr)
	r.ev.reply("agent", true, longReply, "")
	d := r.gate.deliveries()
	if len(d) != 1 {
		t.Fatalf("submitted %d", len(d))
	}
	if opDeliver != mail.OpDeliver || mailExecutor != mail.Tool {
		t.Fatal("the mail adapter's names changed")
	}
	in := d[0]
	if in.Origin != grants.OriginEvidence || in.Action != mail.OpDeliver || in.Account != "mail" || in.Executor != "mail" ||
		len(in.Recipients) != 1 || in.Recipients[0] != destAddr || in.Params[grants.ParamBody] != longReply ||
		in.Params[grants.ParamFrom] != grants.DeliverFromAgent || len(in.Params) != 2 {
		t.Fatalf("delivery intent %+v", in)
	}
	if got := r.texts(); len(got) != 1 || got[0] != "Your landlord agreed to fix the boiler on Thursday. "+pointer {
		t.Fatalf("texted %q", got)
	}
	r.ev.reply("agent", false, "Public news.", "")
	if len(r.gate.deliveries()) != 1 || r.texts()[1] != "Public news." {
		t.Fatalf("public reply: %q", r.texts())
	}
	n := newEvRig(t, "")
	n.ev.reply("agent", true, "Short reply.", "")
	if len(n.gate.subs) != 0 || n.texts()[0] != "Short reply." {
		t.Fatalf("no destination: %q", n.texts())
	}
	u := newEvRig(t, destAddr)
	u.ev.mail = nil
	u.ev.reply("agent", true, "Short reply.", "")
	if len(u.gate.subs) != 0 || u.texts()[0] != "Short reply." {
		t.Fatalf("no mail account: %q", u.texts())
	}
}

// TestRedirectedTextsFitOneMessage: the summary is the agent's own when it
// gave one, else the reply's opening sentences, never only a filler
// opening; cut so the text with its prefix fits one SMS; and left out
// when it looks like a code or key or there is no room (UX U4, CH-19,
// security C6).
func TestRedirectedTextsFitOneMessage(t *testing.T) {
	r := newEvRig(t, destAddr)
	r.ev.reply("agent", true, strings.Repeat("word ", 100), "")
	r.ev.reply("agent", true, "First line\nsecond line", "")
	r.ev.reply("agent", true, "Your login code is 482913. Use it soon.", "")
	r.ev.reply("agent", true, longReply, "Boiler fixed Thursday; rent letter attached.")
	r.ev.reply("agent", true, "Sure! I looked at your three bank statements and found two duplicate charges.", "")
	r.ev.reply("agent", true, longReply, "  Your code\n is 482913 ")
	got := r.texts()
	for _, s := range got {
		if len(owner.AgentPrefix+s) > smsSegment || !strings.HasSuffix(s, pointer) {
			t.Fatalf("text %q (%d)", s, len(owner.AgentPrefix+s))
		}
	}
	want := []string{"", "First line second line " + pointer, pointer, "Boiler fixed Thursday; rent letter attached. " + pointer,
		"Sure! I looked at your three bank statements and found two duplicate charges. " + pointer, pointer}
	for i, w := range want {
		if w != "" && got[i] != w {
			t.Fatalf("text %d: %q, want %q", i, got[i], w)
		}
	}
	if !strings.HasPrefix(got[0], "word word") || !strings.Contains(got[0], "... ") {
		t.Fatalf("long summary %q", got[0])
	}
	// With room for only a few words, no summary at all.
	tight := newEvRig(t, "o@"+strings.Repeat("d", smsSegment-len(owner.AgentPrefix)-1-len(pointer)+len("example.test")-minSummary+1)+".t")
	tight.ev.reply("agent", true, longReply, "")
	if !strings.HasPrefix(tight.texts()[0], "Full reply sent to o***@ddd") {
		t.Fatalf("tight: %q", tight.texts()[0])
	}
	long := newEvRig(t, "o@"+strings.Repeat("d", 200)+".test")
	long.ev.reply("agent", true, longReply, "")
	if !strings.HasPrefix(long.texts()[0], "Full reply sent to o***@ddd") {
		t.Fatalf("long domain: %q", long.texts()[0])
	}
}

// noPage: until the local page shows kept replies, no text names it
// (UX U2).
func noPage(t *testing.T, s string) {
	t.Helper()
	if strings.Contains(strings.ToLower(s), "page") {
		t.Fatalf("text names a page: %q", s)
	}
}

// TestLongRepliesAreKept: with no destination, a reply too long for one
// text is kept whole and the text says so (potency C1).
func TestLongRepliesAreKept(t *testing.T) {
	if maxText != control.MaxText {
		t.Fatal("the owner channel's text limit changed")
	}
	r := newEvRig(t, "")
	long := strings.Repeat("All of this is the reply. ", 30)
	r.ev.reply("agent", true, long, "")
	got := r.texts()[0]
	if len(owner.AgentPrefix+got) > control.MaxText || !strings.HasSuffix(got, " "+keptLong) || !strings.HasPrefix(got, "All of this") {
		t.Fatalf("text %q", got)
	}
	noPage(t, got)
	if k := r.ev.kept.list(); len(k) != 1 || k[0].Text != long {
		t.Fatalf("kept %+v", k)
	}
	fits := strings.Repeat("x", control.MaxText-len(owner.AgentPrefix))
	r.ev.reply("agent", false, fits, "")
	if r.texts()[1] != fits || len(r.ev.kept.list()) != 1 {
		t.Fatal("a reply that fits was kept")
	}
}

// TestAFailedDeliveryIsRetriedThenKept: a delivery that does not succeed
// is tried again a bounded number of times; then the private reply is
// kept, never texted, the text says why and what to do, and STATUS says
// deliveries are failing until one works (UX U2, U5). A refusal or the
// day's cap is not retried (security C5).
func TestAFailedDeliveryIsRetriedThenKept(t *testing.T) {
	for _, st := range []journal.State{journal.NotApplied, journal.OutcomeUnknown, journal.Pending} {
		r := newEvRig(t, destAddr)
		r.gate.state = st
		r.ev.reply("agent", true, longReply, "")
		if n := len(r.gate.deliveries()); n != len(deliverRetries)+1 || !slices.Equal(r.slept, deliverRetries) {
			t.Fatalf("%s: %d attempts, slept %v", st, n, r.slept)
		}
		got := r.texts()
		if len(got) != 1 || strings.Contains(got[0], "rent") || !strings.HasSuffix(got[0], failNote) {
			t.Fatalf("%s: texted %q", st, got)
		}
		noPage(t, got[0])
		if k := r.ev.kept.list(); len(k) != 1 || k[0].Text != longReply {
			t.Fatalf("%s: kept %+v", st, k)
		}
		if r.ev.note() == "" {
			t.Fatalf("%s: STATUS does not say deliveries fail", st)
		}
		noPage(t, r.ev.note())
		r.gate.state = journal.Succeeded
		r.ev.reply("agent", true, "Next.", "")
		if r.ev.note() != "" {
			t.Fatalf("still failing after a delivery: %q", r.ev.note())
		}
	}
	r := newEvRig(t, destAddr)
	r.gate.states = []journal.State{journal.NotApplied}
	r.ev.reply("agent", true, longReply, "")
	if n := len(r.gate.deliveries()); n != 2 || !strings.HasSuffix(r.texts()[0], pointer) || len(r.ev.kept.list()) != 0 {
		t.Fatalf("retry that worked: %d %q", n, r.texts())
	}
	for _, c := range []struct{ reason, tail string }{{grants.DeliveryCapReason, capNote}, {"no grant", failNote}} {
		r := newEvRig(t, destAddr)
		r.gate.state, r.gate.reason = journal.Denied, c.reason
		r.ev.reply("agent", true, longReply, "")
		if n := len(r.gate.deliveries()); n != 1 || len(r.slept) != 0 || !strings.HasSuffix(r.texts()[0], c.tail) || len(r.ev.kept.list()) != 1 {
			t.Fatalf("%s: %d attempts, %q", c.reason, n, r.texts())
		}
		noPage(t, r.texts()[0])
	}
	r = newEvRig(t, destAddr)
	r.gate.state = journal.Denied
	for i := 0; i < maxKept+5; i++ {
		r.ev.reply("agent", true, fmt.Sprintf("reply %d.", i), "")
	}
	if k := r.ev.kept.list(); len(k) != maxKept || k[0].Text != "reply 5." {
		t.Fatalf("kept %d, first %+v", len(k), k[0])
	}
	r.now = r.now.Add(keepReplies + time.Minute)
	r.ev.reply("agent", true, "late.", "")
	if k := r.ev.kept.list(); len(k) != 1 || k[0].Text != "late." {
		t.Fatalf("expired replies kept: %d", len(k))
	}
	// On disk, only the broker reads it.
	path := filepath.Join(t.TempDir(), "kept.json")
	k := &keptReplies{store: change.FileStore{Path: path}, now: time.Now}
	k.keep("x")
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("kept file %v %v", fi, err)
	}
}

// TestRepliesKeepTheirOrder: the worker routes replies one at a time, in
// the order the guests sent them.
func TestRepliesKeepTheirOrder(t *testing.T) {
	r := newEvRig(t, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.ev.q = make(chan evidenceJob, 2)
	go r.ev.run(ctx)
	for i := 0; i < 5; i++ {
		r.ev.enqueue("agent", true, fmt.Sprint(i), "")
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(r.texts()) < 5 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := r.texts(); !slices.Equal(got, []string{"0", "1", "2", "3", "4"}) {
		t.Fatalf("order %q", got)
	}
}

// TestEvidenceSetting: EVIDENCE ON, TO and OFF, only in an unlocked
// session. ON and TO say what they do and are asked by the gate (high
// tier with the local page); only the account's own address is taken, and
// a refusal names the one that works (UX U3, U7). OFF needs no code and
// first tells the old destination (security C3). Before mail is wired,
// each says so (UX U1).
func TestEvidenceSetting(t *testing.T) {
	ctx := context.Background()
	r := newEvRig(t, "")
	r.gate.state = journal.Pending
	for _, msg := range []string{"evidence", "evidence to me", "please evidence on", "EVIDENCE OFF now", "evidence of the leak"} {
		if got, ok := r.ev.settings(ctx, msg, true); ok {
			t.Fatalf("%q taken: %q", msg, got)
		}
	}
	for _, msg := range []string{"EVIDENCE ON", "EVIDENCE TO owner@example.test", "EVIDENCE OFF"} {
		if _, ok := r.ev.settings(ctx, msg, false); ok || len(r.gate.subs) != 0 {
			t.Fatalf("a locked session took %q", msg)
		}
	}
	if got, ok := r.ev.settings(ctx, "Evidence on", true); !ok || got != evidenceEffect || len(r.gate.subs) != 1 {
		t.Fatalf("on: %q %v", got, ok)
	}
	in := r.gate.subs[0]
	if in.Origin != grants.OriginOwner || in.Action != journal.ActionEvidence ||
		in.Params[grants.ParamEvidenceAddress] != destAddr || in.Params[grants.ParamEvidenceAccount] != "mail" {
		t.Fatalf("intent %+v", in)
	}
	if got, _ := r.ev.settings(ctx, "evidence to Alias@Example.test", true); got != evidenceEffect || r.gate.subs[1].Params[grants.ParamEvidenceAddress] != "alias@example.test" {
		t.Fatalf("to alias: %q", got)
	}
	got, _ := r.ev.settings(ctx, "evidence to eve@example.net", true)
	if len(r.gate.subs) != 2 || !strings.Contains(got, "o***@example.test") || !strings.Contains(got, "EVIDENCE ON") {
		t.Fatalf("other address: %q", got)
	}
	r.gate.state, r.gate.reason = journal.Denied, "no local page"
	if got, _ := r.ev.settings(ctx, "EVIDENCE ON", true); got != "Not changed: no local page." {
		t.Fatalf("denied: %q", got)
	}
	if got, _ := r.ev.settings(ctx, "EVIDENCE OFF", true); got != evidenceNone {
		t.Fatalf("off with none: %q", got)
	}

	// OFF tells the old destination, then clears it.
	o := newEvRig(t, destAddr)
	n := len(o.gate.subs)
	if got, _ := o.ev.settings(ctx, "evidence off", true); got != evidenceOff {
		t.Fatalf("off: %q", got)
	}
	subs := o.gate.subs[n:]
	if len(subs) != 2 || subs[0].Action != opDeliver || subs[0].Params[grants.ParamFrom] != grants.DeliverFromBox ||
		subs[0].Recipients[0] != destAddr || !strings.HasPrefix(subs[0].Params[grants.ParamBody].(string), "Evidence delivery was turned off by text at 09:00") ||
		subs[1].Action != journal.ActionEvidence || subs[1].Params[grants.ParamEvidenceAddress] != "" {
		t.Fatalf("off submitted %+v", subs)
	}
	if a, _ := o.gate.Evidence(); a != "" {
		t.Fatalf("not cleared: %q", a)
	}
	if d := o.ev.digestLines(); len(d) != 1 || !strings.Contains(d[0], "turned off by text") {
		t.Fatalf("digest %q", d)
	}
	// The notice is tried once: the owner's text is not held up by
	// retries, and OFF works even if the notice fails.
	f := newEvRig(t, destAddr)
	f.gate.states = []journal.State{journal.NotApplied}
	if got, _ := f.ev.settings(ctx, "EVIDENCE OFF", true); got != evidenceOff || len(f.gate.deliveries()) != 1 || len(f.slept) != 0 {
		t.Fatalf("off with a failed notice: %q, %d attempts", got, len(f.gate.deliveries()))
	}

	// Not wired yet.
	u := newEvRig(t, "")
	u.ev.mail = nil
	for _, msg := range []string{"EVIDENCE ON", "EVIDENCE OFF", "evidence to owner@example.test"} {
		if got, _ := u.ev.settings(ctx, msg, true); got != evidenceNotYet || len(u.gate.subs) != 0 {
			t.Fatalf("%q unwired: %q", msg, got)
		}
	}
	var cfg daemon.Config
	cfg.Settings = func(context.Context, string, bool) (string, bool) { return "loops", true }
	u.ev.wire(&cfg)
	if got, _ := cfg.Settings(ctx, "LOOPS OFF", true); got != "loops" {
		t.Fatalf("passed on: %q", got)
	}
	if got, _ := cfg.Settings(ctx, "EVIDENCE OFF", true); got != evidenceNotYet || len(cfg.Notes) != 1 || cfg.Grants.Destination != nil {
		t.Fatalf("wired: %q", got)
	}
	r.ev.wire(&cfg)
	if cfg.Grants.Destination == nil {
		t.Fatal("the gate cannot check the destination")
	}
	var unset evidence
	unset.mail = fakeMailbox{}
	if got, ok := unset.settings(ctx, "EVIDENCE OFF", true); !ok || got != evidenceStarting {
		t.Fatalf("before the daemon runs: %q", got)
	}
}

// TestDigestConfirmsTheDestinationOnce: STATUS does not show a working
// destination; the digest confirms a new one once (UX U5).
func TestDigestConfirmsTheDestinationOnce(t *testing.T) {
	r := newEvRig(t, "")
	if d := r.ev.digestLines(); len(d) != 0 {
		t.Fatalf("digest %q", d)
	}
	r.gate.addr = destAddr
	if d := r.ev.digestLines(); len(d) != 1 || d[0] != "Private replies now come by email to o***@example.test." {
		t.Fatalf("digest %q", d)
	}
	if d := r.ev.digestLines(); len(d) != 0 || r.ev.note() != "" {
		t.Fatalf("again: %q %q", d, r.ev.note())
	}
}

type fakeCases struct{ ids []string }

func (f *fakeCases) ForgetTasks(ids ...string) (int, error) {
	f.ids = append(f.ids, ids...)
	return len(ids), errors.New("cases")
}

// TestADeletionForgetsKeptReplies: a deletion's reach (CAP-3) forgets
// every kept reply, which may quote the deleted record (security C6), as
// well as the learning plane's cases.
func TestADeletionForgetsKeptReplies(t *testing.T) {
	r := newEvRig(t, "")
	r.ev.kept.keep("quotes the record")
	c := &fakeCases{}
	n, err := forgetFan{cases: c, kept: r.ev.kept}.ForgetTasks("agent/1")
	if n != 1 || err == nil || !slices.Equal(c.ids, []string{"agent/1"}) || len(r.ev.kept.list()) != 0 {
		t.Fatalf("forgot %d %v %v %d", n, err, c.ids, len(r.ev.kept.list()))
	}
	r.ev.kept.keep("again")
	if _, err := (forgetFan{kept: r.ev.kept}).ForgetTasks(); err != nil || len(r.ev.kept.list()) != 0 {
		t.Fatalf("without learning: %v", err)
	}
}
