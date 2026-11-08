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
func (b *book) plan(id string, k key.Key) {
	st := kernel.PlanStep{Verb: key.Trash, Clerk: "mail", Args: map[string]string{"target": id}}
	p := kernel.SignPlan(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{st, st}}, b.holder.priv)
	seq := b.add(kernel.TPlanSubmit, p)
	b.add(kernel.TPlanAccepted, map[string]any{"plan": id, "cause": seq, "root": k.Tip(), "scopes": []key.ID{k.Tip()}})
}

func (b *book) dispatch(id string, index int) {
	b.add(kernel.TStepDispatch, map[string]any{"plan": id, "index": index, "attempt": 1, "idem": kernel.Idem(id, index)})
}

// subject is a subject ID as OpenSubject draws them.
const subject = "0123456789abcdef0123456789abcdef"

func (b *book) judge() error { return stopsHold([]key.PublicKey{b.owner.pk}, b.es) }

func (b *book) task(id string) key.Key {
	k, err := key.Derive(b.clerk, b.holder.priv, b.holder.pub, key.LimitTask(id))
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
