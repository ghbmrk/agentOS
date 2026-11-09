package sim

// REQ: KRN-5, KRN-7, KEY-8, LOG-4

import (
	"encoding/json"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// book writes a log by hand, in the shapes the kernel logs, so stopsHold can
// be shown a log the fixed kernel would never write: the fix-free kernel's.
type book struct {
	t      *testing.T
	owner  keyPair
	holder keyPair
	clerk  key.Key
	es     []kernel.Entry
}

func newBook(t *testing.T) *book {
	r := rand.New(rand.NewPCG(1, 2))
	b := &book{t: t, owner: gen(r), holder: gen(r)}
	root := key.Issue(b.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "r"})
	ck, err := key.ClerkKey(root, b.owner.pass, b.holder.pub, 0, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	b.clerk = ck
	return b
}

func (b *book) add(typ string, body any) uint64 {
	raw, err := json.Marshal(body)
	if err != nil {
		b.t.Fatal(err)
	}
	seq := uint64(len(b.es) + 1)
	b.es = append(b.es, kernel.Entry{Seq: seq, At: int64(seq), Type: typ, V: 1, Body: raw})
	return seq
}

// plan logs plan id under k, accepted, with two steps.
func (b *book) plan(id string, k key.Key) { b.accept(id, k, b.submit(id, k)) }

// submit logs plan id under k, with two steps, and returns its entry.
func (b *book) submit(id string, k key.Key) uint64 {
	st := kernel.PlanStep{Verb: key.Trash, Clerk: "mail", Args: map[string]string{"target": id}}
	return b.add(kernel.TPlanSubmit, kernel.SignPlan(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{st, st}}, b.holder.priv))
}

// accept logs plan id's acceptance, caused by its submit entry seq.
func (b *book) accept(id string, k key.Key, seq uint64) {
	b.add(kernel.TPlanAccepted, map[string]any{"plan": id, "cause": seq, "root": k.Tip(), "scopes": []key.ID{k.Tip()}})
}

func (b *book) dispatch(id string, index int) {
	b.add(kernel.TStepDispatch, map[string]any{"plan": id, "index": index, "attempt": 1, "idem": kernel.Idem(id, index)})
}

// subject is a subject ID as OpenSubject draws them.
const subject = "0123456789abcdef0123456789abcdef"

func (b *book) judge() error { return stopsHold([]key.PublicKey{b.owner.pk}, b.es) }

func (b *book) task(id string, cav ...key.Caveat) key.Key {
	k, err := key.Derive(b.clerk, b.holder.priv, b.holder.pub, append([]key.Caveat{key.LimitTask(id)}, cav...)...)
	if err != nil {
		b.t.Fatal(err)
	}
	return k
}

// Each narrowing the fix-free kernel outran is named; a plan it did not reach,
// and a step the owner retried, are not.
func TestStopsHoldNamesEachNarrowingOutrun(t *testing.T) {
	for name, c := range map[string]struct {
		write func(*book)
		want  string // "" for a log that holds
	}{
		"dispatch before any narrowing": {func(b *book) {
			b.plan("p1", b.clerk)
			b.dispatch("p1", 0)
		}, ""},
		"STOP, RESUME, dispatch": {func(b *book) {
			b.plan("p1", b.clerk)
			b.add(kernel.TStop, struct{}{})
			b.add(kernel.TResume, struct{}{})
			b.dispatch("p1", 0)
		}, "after a STOP reached it"},
		"a plan still pending at the STOP": {func(b *book) {
			seq := b.submit("p1", b.clerk)
			b.add(kernel.TStop, struct{}{})
			b.add(kernel.TResume, struct{}{})
			b.accept("p1", b.clerk, seq)
			b.dispatch("p1", 0)
		}, "after a STOP reached it"},
		"a plan submitted after the STOP": {func(b *book) {
			b.add(kernel.TStop, struct{}{})
			b.add(kernel.TResume, struct{}{})
			b.plan("p1", b.clerk)
			b.dispatch("p1", 0)
		}, ""},
		"retried after the STOP": {func(b *book) {
			b.plan("p1", b.clerk)
			b.add(kernel.TStop, struct{}{})
			b.add(kernel.TResume, struct{}{})
			b.add(kernel.TStepRetried, map[string]any{"plan": "p1", "index": 0})
			b.dispatch("p1", 0)
		}, ""},
		"retried, then its next step": {func(b *book) {
			b.plan("p1", b.clerk)
			b.add(kernel.TStop, struct{}{})
			b.add(kernel.TResume, struct{}{})
			b.add(kernel.TStepRetried, map[string]any{"plan": "p1", "index": 0})
			b.dispatch("p1", 1)
		}, "step 1 of p1 after a STOP"},
		"its task's end": {func(b *book) {
			b.add(kernel.TTaskOpened, map[string]any{"id": "t1"})
			b.plan("p1", b.task("t1"))
			b.add(kernel.TTaskEnded, map[string]any{"task": "t1"})
			b.dispatch("p1", 0)
		}, "after its task's end reached it"},
		"another task's end": {func(b *book) {
			b.add(kernel.TTaskOpened, map[string]any{"id": "t1"})
			b.add(kernel.TTaskOpened, map[string]any{"id": "t2"})
			b.plan("p1", b.task("t1"))
			b.add(kernel.TTaskEnded, map[string]any{"task": "t2"})
			b.dispatch("p1", 0)
		}, ""},
		"a task never opened": {func(b *book) {
			b.plan("p1", b.task("t9"))
			b.dispatch("p1", 0)
		}, "for task t9, not live"},
		"a revoke of its key": {func(b *book) {
			b.plan("p1", b.clerk)
			b.add(kernel.TKeyRevoked, map[string]any{"ID": b.clerk.Tip()})
			b.dispatch("p1", 0)
		}, "after a revoke reached it"},
		"a revoke of another key": {func(b *book) {
			b.plan("p1", b.clerk)
			b.add(kernel.TKeyRevoked, map[string]any{"ID": key.ID{1}})
			b.dispatch("p1", 0)
		}, ""},
		"an erase of what its lineage read": {func(b *book) {
			h := kernel.Hash{7}
			b.add(kernel.TSubjectOpened, map[string]any{"subject": subject, "key_id": "k"})
			b.add(kernel.TContentStored, map[string]any{"subject": subject, "store": "mail", "hash": h, "class": "message"})
			b.add(kernel.TContentRead, map[string]any{"hash": h, "lineage": "g1"})
			b.plan("g1/p1", b.clerk)
			b.plan("g2/p1", b.clerk)
			b.add(kernel.TSubjectErased, map[string]any{"subject": subject, "stores": []string{"mail"}})
			b.dispatch("g2/p1", 0)
			b.dispatch("g1/p1", 0)
		}, "step 0 of g1/p1 after an erase"},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBook(t)
			c.write(b)
			err := b.judge()
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("a log that holds: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// A log the fold refuses is reported, not judged.
func TestStopsHoldReportsAnUnfoldableLog(t *testing.T) {
	b := newBook(t)
	b.add(kernel.TStop, struct{}{})
	b.es[0].Seq = 5
	if err := b.judge(); err == nil {
		t.Fatal("a log out of order was judged")
	}
}

// booted writes the book into a booted kernel's log without folding it, as
// only a fix-free kernel would have written it.
func (b *book) booted() *kernel.Kernel {
	head := gen(rand.New(rand.NewPCG(3, 4)))
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{},
		Pub: head.pub, Sign: head.priv, Rand: rand.NewChaCha8([32]byte{})})
	if err != nil {
		b.t.Fatal(err)
	}
	k, err := kernel.Boot(l, []key.PublicKey{b.owner.pk}, nil, 0)
	if err != nil {
		b.t.Fatal(err)
	}
	for _, e := range b.es {
		if _, err := k.Log().Append(e.At, e.Type, e.V, json.RawMessage(e.Body)); err != nil {
			b.t.Fatal(err)
		}
	}
	return k
}

// The sim's boot check and the erase sim's judge each run stopsHold on the
// whole log, and report its finding rather than a later check's.
func TestTheSimsJudgeNarrowingsOutrun(t *testing.T) {
	b := newBook(t)
	b.plan("p1", b.clerk)
	b.add(kernel.TStop, struct{}{})
	b.add(kernel.TResume, struct{}{})
	b.dispatch("p1", 0)
	k := b.booted()
	anchors := []key.PublicKey{b.owner.pk}
	for name, judge := range map[string]func() error{
		"rederive at boot": func() error { return (&sim{k: k, w: &world{anchors: anchors}}).rederive() },
		"erase judge":      func() error { return judgeErase(k, anchors, crashKeys{}, nil, nil, nil, nil) },
	} {
		if err := judge(); err == nil || !strings.Contains(err.Error(), "after a STOP reached it") {
			t.Errorf("%s: got %v, want the STOP outrun", name, err)
		}
	}
}

// A log no narrowing was outrun in, whose plan was accepted under a key the
// owner never granted, fails the boot check on Rederive (KRN-1).
func TestTheSimsBootCheckRederives(t *testing.T) {
	b := newBook(t)
	b.plan("p1", b.clerk)
	anchors := []key.PublicKey{b.owner.pk}
	if err := stopsHold(anchors, b.es); err != nil {
		t.Fatal(err)
	}
	err := (&sim{k: b.booted(), w: &world{anchors: anchors}}).rederive()
	if err == nil || !strings.Contains(err.Error(), "invariant: rederive") {
		t.Fatalf("got %v, want Rederive's divergence", err)
	}
}

// tally counts what the task and STOP ops left: a STOP with a RESUME as the
// very next entry at its time, each task's open and end, of the plans
// serving a task those its end cancelled or ended, and the held steps under
// a hold longer than a task that its timeout (not an earlier end) cancelled.
func TestTallyCountsWhatTheTaskOpsLeft(t *testing.T) {
	b := newBook(t)
	body := func(v any) []byte { raw, _ := json.Marshal(v); return raw }
	es := []kernel.Entry{
		{Type: kernel.TStop, At: 4}, {Type: kernel.TResume, At: 4}, // resumed at once
		{Type: kernel.TStop, At: 5}, {Type: kernel.TResume, At: 5}, // and again
		{Type: kernel.TStop, At: 6}, {Type: kernel.TResume, At: 7}, // a tick between
		{Type: kernel.TTaskOpened, At: 10, Body: body(map[string]string{"id": "t1"})},
		{Type: kernel.TTaskOpened, At: 10, Body: body(map[string]string{"id": "t2"})},
		{Type: kernel.TTaskOpened, At: 10, Body: body(map[string]string{"id": "t3"})},
		{Type: kernel.TTaskEnded, At: 20, Body: body(map[string]string{"task": "t3"})},
		{Type: kernel.TTaskEnded, At: kernel.TaskTimeout + 5, Body: body(map[string]string{"task": "t2"})},  // before its timeout
		{Type: kernel.TTaskEnded, At: kernel.TaskTimeout + 10, Body: body(map[string]string{"task": "t1"})}, // at it
		{Type: kernel.TResume, At: 8}, {Type: kernel.TStop, At: 8}, // a STOP last
	}
	held := []kernel.StepState{
		{HeldSeq: 3, Phase: kernel.PCancelled}, // one a timeout cancelled
		{Phase: kernel.PCancelled},             // not held
		{HeldSeq: 4, Phase: kernel.PDone},      // sent
	}
	st := kernel.NewState(nil)
	long := key.LimitHold(hour, 30*hour) // a hold longer than a task
	for id, p := range map[string]*kernel.PlanState{
		"plain":     {Plan: kernel.Plan{Key: b.clerk}, Cancel: kernel.CTask},
		"cancelled": {Plan: kernel.Plan{Key: b.task("t1", long)}, Cancel: kernel.CTask, Steps: append([]kernel.StepState{held[0], held[0]}, held...)},
		"short":     {Plan: kernel.Plan{Key: b.task("t1", key.LimitHold(hour, hour))}, Cancel: kernel.CTask, Steps: held},
		"a day":     {Plan: kernel.Plan{Key: b.task("t1", key.LimitHold(hour, kernel.TaskTimeout))}, Cancel: kernel.CTask, Steps: held},
		"early":     {Plan: kernel.Plan{Key: b.task("t2", long)}, Cancel: kernel.CTask, Steps: held},
		"ended":     {Plan: kernel.Plan{Key: b.task("t1")}, Ended: kernel.CTask},
		"stopped":   {Plan: kernel.Plan{Key: b.task("t1", long)}, Cancel: key.RStopped, Steps: held},
		"live":      {Plan: kernel.Plan{Key: b.task("t1")}},
	} {
		st.Order = append(st.Order, id)
		st.Plans[id] = p
	}
	var r Result
	r.tally(st, es)
	if r.StopResumed != 2 || r.TasksOpened != 3 || r.TasksEnded != 3 || r.EndedEarly != 2 || r.TaskPlans != 7 || r.TaskCancels != 5 || r.TimedOut != 3 {
		t.Fatalf("tally %+v", r)
	}
}

// A task opened while no key is live gets no plan, and no error.
func TestATaskWithNoLiveKeyGetsNoPlan(t *testing.T) {
	s := &sim{k: newBook(t).booted()}
	if err := s.taskPlan("t1"); err != nil || s.submits != 0 {
		t.Fatalf("got %v after %d submits, want none", err, s.submits)
	}
}
