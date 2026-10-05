package grants

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// fakeOwner stands in for owner.Channel: it records requests and replies
// and leaves deciding to the test.
type fakeOwner struct {
	mu     sync.Mutex
	limits owner.Limits
	now    func() time.Time
	reqs   map[string][]owner.Item
	order  []string
	queued []owner.AutoReply
	due    []owner.Queued
	notes  []string
	commit bool // QueueAutoReply turns replies into requests
	down   bool // Request fails
	active bool // the owner is texting
}

func (f *fakeOwner) Request(items []owner.Item, _ time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return "", fmt.Errorf("owner: no modem")
	}
	id := fmt.Sprintf("R%d", len(f.order)+1)
	f.reqs[id] = append([]owner.Item(nil), items...)
	f.order = append(f.order, id)
	return id, nil
}

func (f *fakeOwner) Tier(fa owner.Facts) owner.Tier { return owner.Classify(fa, f.limits, f.now()) }

func (f *fakeOwner) Active(time.Duration) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active
}

func (f *fakeOwner) QueueAutoReply(ar owner.AutoReply) (owner.QueueResult, error) {
	if f.commit {
		id, err := f.Request([]owner.Item{{Ref: ar.Ref, Object: "reply (date)", Facts: ar.Facts}}, 0)
		return owner.QueueResult{Request: id, Matched: "date"}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queued = append(f.queued, ar)
	q := owner.Queued{ID: fmt.Sprintf("Q%d", len(f.queued)), SendAt: f.now().Add(10 * time.Minute), Reply: ar}
	f.due = append(f.due, q)
	return owner.QueueResult{Queued: &q}, nil
}

func (f *fakeOwner) DueAutoReplies() []owner.Queued {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out, keep []owner.Queued
	for _, q := range f.due {
		if !f.now().Before(q.SendAt) {
			out = append(out, q)
		} else {
			keep = append(keep, q)
		}
	}
	f.due = keep
	return out
}

func (f *fakeOwner) Notify(text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notes = append(f.notes, text)
	return nil
}

// last returns the newest request.
func (f *fakeOwner) last(t *testing.T) (string, []owner.Item) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.order) == 0 {
		t.Fatal("no request was sent to the owner")
	}
	id := f.order[len(f.order)-1]
	return id, f.reqs[id]
}

func (f *fakeOwner) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.order)
}

// fakeExec counts executions per intent.
type fakeExec struct {
	mu  sync.Mutex
	ran map[string]int
}

func (e *fakeExec) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ran[in.ID]++
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "sent"}
}

func (e *fakeExec) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultUnknown}
}

func (e *fakeExec) runs(id string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ran[id]
}

// fakeVerifier answers from source records keyed by the record param.
type fakeVerifier struct {
	mu      sync.Mutex
	records map[string]Verified
}

func (v *fakeVerifier) Verify(_ context.Context, in journal.Intent) (Verified, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	rec, _ := in.Params[ParamRecord].(string)
	r, ok := v.records[rec]
	if !ok {
		return Verified{}, fmt.Errorf("no record %q", rec)
	}
	return r, nil
}

func (v *fakeVerifier) set(rec string, x Verified) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.records[rec] = x
}

type rig struct {
	t     *testing.T
	store *journal.MemStore
	cfg   Config
	eng   *journal.Engine
	g     *Gate
	own   *fakeOwner
	exec  *fakeExec
	ver   *fakeVerifier
	clock time.Time
	cmu   sync.Mutex
}

func (r *rig) now() time.Time {
	r.cmu.Lock()
	defer r.cmu.Unlock()
	return r.clock
}

func (r *rig) advance(d time.Duration) {
	r.cmu.Lock()
	r.clock = r.clock.Add(d)
	r.cmu.Unlock()
}

func newRig(t *testing.T, edit func(*Config)) *rig {
	r := &rig{t: t, store: &journal.MemStore{}, clock: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC),
		exec: &fakeExec{ran: map[string]int{}}, ver: &fakeVerifier{records: map[string]Verified{}}}
	r.cfg = Config{Declared: map[string]map[string]string{"mail": mailOps(), "cal": {"event.add": "draft"}}, Verifiers: map[string]Verifier{"mail": r.ver}, LocalUI: true, Now: r.now}
	if edit != nil {
		edit(&r.cfg)
	}
	r.open()
	return r
}

// open starts a gate and engine on the rig's journal: at first, and again
// to simulate a restart.
func (r *rig) open() {
	r.t.Helper()
	r.own = &fakeOwner{limits: owner.Limits{AmountLimit: 50000}, now: r.now, reqs: map[string][]owner.Item{}}
	r.g = New(r.cfg)
	eng, err := journal.Open(r.store, r.g, map[string]journal.Executor{"mail": r.exec, ExecutorName: r.g},
		func(s string) string { return s }, journal.WithClock(r.now))
	if err != nil {
		r.t.Fatal(err)
	}
	r.eng = eng
	r.g.Attach(eng, r.own)
}

// effect does what the guest plane does for effect_request.
func (r *rig) effect(id, action string, params map[string]any, recips ...string) journal.Status {
	r.t.Helper()
	return r.submit(journal.Intent{ID: id, Origin: "guest:agent", Account: "mail", Action: action,
		Params: params, Recipients: recips, Executor: "mail", Machine: "agent", Label: "private"})
}

func (r *rig) submit(in journal.Intent) journal.Status {
	r.t.Helper()
	st, err := r.g.Submit(in)
	if err != nil {
		r.t.Fatalf("submit %s: %v", in.ID, err)
	}
	if st.State == journal.Pending {
		if st, err = r.g.Authorize(context.Background(), in.ID); err != nil {
			r.t.Fatalf("authorize %s: %v", in.ID, err)
		}
	}
	if st.State == journal.Authorized {
		st, _ = r.g.Dispatch(context.Background(), in.ID)
	}
	return st
}

func (r *rig) state(id string) journal.Status {
	r.t.Helper()
	st, err := r.g.Get(id)
	if err != nil {
		r.t.Fatal(err)
	}
	return st
}

// decide answers the newest request for every item.
func (r *rig) decide(approved bool, why string) {
	r.t.Helper()
	req, items := r.own.last(r.t)
	for i, it := range items {
		r.g.Decide(owner.Decision{Request: req, Item: i + 1, Ref: it.Ref, Approved: approved, Why: why})
	}
	r.g.Wait()
}

func specParams(s Spec) map[string]any {
	b, _ := json.Marshal(s)
	var m map[string]any
	json.Unmarshal(b, &m)
	return map[string]any{"grant": m}
}

// grant creates a grant the way the owner does: code, then local page.
func (r *rig) grant(s Spec) string {
	r.t.Helper()
	id := fmt.Sprintf("local/grant/%d", len(r.eng.List()))
	st := r.submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount,
		Action: journal.ActionGrantChange, Params: specParams(s), Executor: ExecutorName})
	if st.State != journal.Pending {
		r.t.Fatalf("grant %s: %s %q", id, st.State, st.Permission.Reason)
	}
	r.g.Flush()
	r.decide(true, "owner")
	if err := r.g.ConfirmLocal(id); err != nil {
		r.t.Fatal(err)
	}
	r.g.Wait()
	st = r.state(id)
	if st.State != journal.Succeeded {
		r.t.Fatalf("grant %s: %s %q", id, st.State, st.Permission.Reason)
	}
	return st.Attempts[len(st.Attempts)-1].Evidence
}

// mailOps is the mail adapter's own declaration (ADP-2).
func mailOps() map[string]string {
	return map[string]string{
		"message.list": "read", "draft.save": "draft", "message.send": "send",
		"invoice.send": "send", "key.create": "reveal-or-create-secret"}
}

func mailGrant() Spec { return Spec{Account: "mail", Executor: "mail", Ops: mailOps()} }

// sam is a contact the owner created, so sends to sam are low risk.
func sam() Verified {
	return Verified{
		Item: owner.Item{Object: "invoice 1042", Recipient: "sam@example.com", Amount: "$120.00",
			Facts: owner.Facts{RecipientChecked: true, RecipientExists: true, RecipientByOwner: true, HasAmount: true, Amount: 12000}},
		Recipients: []string{"sam@example.com"}, Record: "inv-1042", Edited: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
	}
}
