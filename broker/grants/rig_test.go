package grants

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/owner"
)

// fakeOwner stands in for owner.Channel: it records requests and replies
// and leaves deciding to the test.
type fakeOwner struct {
	mu         sync.Mutex
	limits     owner.Limits
	now        func() time.Time
	reqs       map[string][]owner.Item
	order      []string
	queued     []owner.AutoReply
	due        []owner.Queued
	notes      []string
	commit     bool     // QueueAutoReply turns replies into requests
	down       bool     // Request fails
	lineDown   bool     // Request fails: the owner's line is down
	active     bool     // the owner is texting
	each       []string // requests opened by RequestEach
	local      []string // requests opened by RequestLocalEach
	localCalls int
	lateUndo   map[string]bool // UndoneAfterRelease
}

func (f *fakeOwner) Request(items []owner.Item, _ time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return "", fmt.Errorf("owner: no modem")
	}
	if f.lineDown {
		return "", modem.ErrDown
	}
	for _, it := range items {
		if !owner.SMSApprovable(it) {
			return "", owner.ErrLocalOnly // as the channel refuses it
		}
	}
	id := fmt.Sprintf("R%d", len(f.order)+1)
	f.reqs[id] = append([]owner.Item(nil), items...)
	f.order = append(f.order, id)
	return id, nil
}

// RequestLocalEach records requests asked on the local page (P2-2a),
// one call per flush (Potency R2).
func (f *fakeOwner) RequestLocalEach(items []owner.Item, _ []time.Duration) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.localCalls++
	ids := make([]string, len(items))
	if f.down {
		return ids, fmt.Errorf("owner: no modem")
	}
	if f.lineDown {
		return ids, modem.ErrDown
	}
	for i, it := range items {
		ids[i] = fmt.Sprintf("R%d", len(f.order)+1)
		f.reqs[ids[i]] = []owner.Item{it}
		f.order = append(f.order, ids[i])
		f.local = append(f.local, ids[i])
	}
	return ids, nil
}

// RequestEach records one request per item, as the channel opens them.
func (f *fakeOwner) RequestEach(items []owner.Item, ttls []time.Duration) ([]string, error) {
	ids := make([]string, len(items))
	for i, it := range items {
		id, err := f.Request([]owner.Item{it}, ttls[i])
		if err != nil {
			return ids, err
		}
		ids[i] = id
		f.mu.Lock()
		f.each = append(f.each, id)
		f.mu.Unlock()
	}
	return ids, nil
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

func (f *fakeOwner) UndoneAfterRelease(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lateUndo[id]
}

func (f *fakeOwner) Inform(text string) error {
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

// fakeExec counts executions per intent and records the last params each
// ran with. An intent in fail is not applied.
type fakeExec struct {
	mu     sync.Mutex
	ran    map[string]int
	params map[string]map[string]any
	fail   map[string]bool
	// evidence overrides a failed intent's evidence.
	evidence map[string]string
	// block holds an intent's attempts until its channel is closed.
	block map[string]chan struct{}
}

func (e *fakeExec) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	e.mu.Lock()
	b := e.block[in.ID]
	e.mu.Unlock()
	if b != nil {
		<-b
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ran[in.ID]++
	if e.params == nil {
		e.params = map[string]map[string]any{}
	}
	e.params[in.ID] = in.Params
	if e.fail[in.ID] {
		ev := "changed since"
		if x := e.evidence[in.ID]; x != "" {
			ev = x
		}
		return journal.Outcome{Result: journal.ResultNotApplied, Evidence: ev}
	}
	return journal.Outcome{Result: journal.ResultSucceeded, Evidence: "done:" + in.ID}
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
	// redact is the journal's redactor; nil keeps text as it is.
	redact journal.Redactor
	g      *Gate
	own    *fakeOwner
	exec   *fakeExec
	ver    *fakeVerifier
	clock  time.Time
	cmu    sync.Mutex
	// boot is what the next open's owner channel hands back as carried
	// over a restart (owner Boot calling Reissue).
	boot []owner.Carried
	// execs are more executors to register, such as the change pipeline.
	execs map[string]journal.Executor
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

func newRig(t *testing.T, edit func(*Config)) *rig { return newRigExecs(t, edit, nil) }

// newRigExecs is newRig with more executors registered on the engine.
func newRigExecs(t *testing.T, edit func(*Config), execs map[string]journal.Executor) *rig {
	r := &rig{t: t, store: &journal.MemStore{}, clock: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC),
		exec: &fakeExec{ran: map[string]int{}}, ver: &fakeVerifier{records: map[string]Verified{}}, execs: execs}
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
	r.openWith(func() Owner { return r.own })
	r.g.Reissue(r.boot)
	r.boot = nil
}

// openWith starts a gate and engine with the owner channel mk returns,
// made after the gate exists so it can take the gate's hooks.
func (r *rig) openWith(mk func() Owner) {
	r.t.Helper()
	r.g = New(r.cfg)
	execs := map[string]journal.Executor{"mail": r.exec, ExecutorName: r.g}
	for k, x := range r.execs {
		execs[k] = x
	}
	red := r.redact
	if red == nil {
		red = func(s string) string { return s }
	}
	eng, err := journal.Open(r.store, r.g, execs, red, journal.WithClock(r.now))
	if err != nil {
		r.t.Fatal(err)
	}
	r.eng = eng
	r.g.Attach(eng, mk())
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

// pageDecide approves the last page request as the page does: a fresh code,
// and the sum of each item as shown (sum, when set, stands in for it).
func (r *rig) pageDecide(sum string) {
	r.t.Helper()
	r.own.mu.Lock()
	if len(r.own.local) == 0 {
		r.own.mu.Unlock()
		r.t.Fatal("nothing was asked on the page")
	}
	req := r.own.local[len(r.own.local)-1]
	items := r.own.reqs[req]
	r.own.mu.Unlock()
	for i, it := range items {
		s := owner.ItemSum(it)
		if sum != "" {
			s = sum
		}
		r.g.Decide(owner.Decision{Request: req, Item: i + 1, Ref: it.Ref, Approved: true, Why: "owner", Page: true, Sum: s})
	}
	r.g.Wait()
}

func specParams(s Spec) map[string]any {
	b, _ := json.Marshal(s)
	var m map[string]any
	json.Unmarshal(b, &m)
	return map[string]any{"grant": m}
}

// grant creates a grant the way the owner does: one code on the local page.
func (r *rig) grant(s Spec) string {
	r.t.Helper()
	id := fmt.Sprintf("local/grant/%d", len(r.eng.List()))
	st := r.submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount,
		Action: journal.ActionGrantChange, Params: specParams(s), Executor: ExecutorName})
	if st.State != journal.Pending {
		r.t.Fatalf("grant %s: %s %q", id, st.State, st.Permission.Reason)
	}
	r.g.Flush()
	r.pageDecide("")
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
