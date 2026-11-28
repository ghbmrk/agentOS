package sim

// REQ: EVL-1, LOG-4, CAP-3

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The erase sim's fakes: a disarmed machine counts no write; an armed one
// fails the write it was armed for and every later one, the key table and
// the stores writing nothing then; the log's armed append tears its frame
// and the next append fails.
func TestTheEraseMachineCrashesAtItsWrite(t *testing.T) {
	m := &machine{}
	if err := m.write("key"); err != nil || m.left != 0 || m.crashed {
		t.Fatalf("a disarmed write: %v, left %d", err, m.left)
	}
	m.left = 2
	if err := m.write("key"); err != nil || m.left != 1 {
		t.Fatalf("the write before the crash: %v, left %d", err, m.left)
	}
	if err := m.write("store"); !errors.Is(err, errCrash) || !m.crashed || m.hit != "store" {
		t.Fatalf("the armed write: %v, hit %q", err, m.hit)
	}
	keys := crashKeys{kernel.NewMemKeys(), m}
	stores := crashStore{kernel.NewMemContent(), m}
	if err := keys.Put("s", kernel.SubjectKey{}); !errors.Is(err, errCrash) || len(keys.M) != 0 {
		t.Fatalf("a key put after the crash: %v, %d kept", err, len(keys.M))
	}
	if err := stores.Put(kernel.Hash{}, []byte("x")); !errors.Is(err, errCrash) || len(stores.M) != 0 {
		t.Fatalf("a store put after the crash: %v, %d kept", err, len(stores.M))
	}

	d := &Disk{rng: rand.New(rand.NewPCG(1, 2))}
	lm := &machine{}
	log := crashLog{d, lm}
	if err := log.Append([]byte("a")); err != nil || lm.left != 0 {
		t.Fatalf("a disarmed append: %v, left %d", err, lm.left)
	}
	lm.left = 2
	if err := log.Append([]byte("b")); err != nil || lm.left != 1 || lm.crashed {
		t.Fatalf("the append before the crash: %v, left %d", err, lm.left)
	}
	if err := log.Append([]byte("cdefgh")); err == nil || !lm.crashed || lm.hit != "log" {
		t.Fatalf("the armed append: %v, hit %q", err, lm.hit)
	}
	if err := log.Append([]byte("i")); !errors.Is(err, errCrash) {
		t.Fatalf("an append after the crash: %v", err)
	}
}

// eraseRig is an honest erase, settled: two subjects with an item each, in
// two stores, lineage-0 reading both and submitting a plan after each read,
// lineage-1 one plan before any read; then the first subject erased, and
// ticks ticks a backoff apart, by which every store's delete is confirmed unless down,
// which fails every one.
type eraseRig struct {
	k       *kernel.Kernel
	anchors []key.PublicKey
	keys    crashKeys
	mem     map[string]*kernel.MemContent
	stores  map[string]kernel.ContentStore
	subs    []string
	gone    map[string]bool
	items   map[kernel.Hash]simItem
	hs      []kernel.Hash
	firsts  map[[2]string]int64
	sk      kernel.SubjectKey // the erased subject's key, before the erase
	ct      []byte            // its item's sealed bytes, before the erase
}

func newEraseRig(t *testing.T, ticks int, down bool) *eraseRig {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	rng := rand.New(rand.NewPCG(3, 3))
	head, owner, spare, holder := gen(rng), gen(rng), gen(rng), gen(rng)
	e := &eraseRig{anchors: []key.PublicKey{owner.pk, spare.pk}, gone: map[string]bool{},
		items: map[kernel.Hash]simItem{}, firsts: map[[2]string]int64{}}
	m := &machine{}
	e.keys = crashKeys{kernel.NewMemKeys(), m}
	e.mem = map[string]*kernel.MemContent{"mail": kernel.NewMemContent(), "notes": kernel.NewMemContent()}
	e.stores = map[string]kernel.ContentStore{"mail": crashStore{e.mem["mail"], m}, "notes": crashStore{e.mem["notes"], m}}
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: head.pub, Sign: head.priv, Rand: rand.NewChaCha8([32]byte{1})})
	must(err)
	e.k, err = kernel.Boot(l, e.anchors, nil, 0)
	must(err)
	_, err = e.k.OpenContent(e.keys, e.stores, 0)
	must(err)
	root := key.Issue(owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Unsubscribe}, Serial: "erase"})
	pk, err := key.ClerkKey(root, owner.pass, holder.pub, 0, 1<<40, key.LimitHold(1<<40, 1<<40))
	must(err)
	must(e.k.Issue(-kernel.GrantHold, approve([]key.Key{root, pk}, owner, spare), root, pk))
	now := int64(1)
	submit := func(id string) {
		step := kernel.PlanStep{Verb: key.Unsubscribe, Clerk: "mail", Args: map[string]string{}}
		for _, n := range key.ArgNames(key.Unsubscribe) {
			step.Args[n] = id
		}
		must(e.k.Submit(now, kernel.SignPlan(kernel.Plan{ID: id, Key: pk, Steps: []kernel.PlanStep{step}}, holder.priv)))
		now++
	}
	submit("lineage-1/early")
	for i, store := range []string{"mail", "notes"} {
		s, err := e.k.OpenSubject(now)
		must(err)
		text := fmt.Sprintf("item of %d", i)
		h, err := e.k.Seal(now, s, store, "message", []byte(text))
		must(err)
		e.subs, e.hs, e.items[h] = append(e.subs, s), append(e.hs, h), simItem{text, s, store}
		now++
	}
	for i, h := range e.hs {
		if _, err := e.k.ReadFor(now, h, "lineage-0"); err != nil {
			t.Fatal(err)
		}
		e.firsts[[2]string{e.subs[i], "lineage-0"}] = now
		now++
		submit(fmt.Sprintf("lineage-0/after-%d", i))
	}
	submit("lineage-0.x/shares-a-prefix")
	must(e.k.Tick(now))
	e.sk, _, _ = e.keys.Get(e.subs[0])
	e.ct, _ = e.mem["mail"].Get(e.hs[0])
	e.gone[e.subs[0]] = true
	m.flaky, m.rng = down, rand.New(always{})
	_, err = e.k.Erase(now, e.subs[0])
	must(err)
	for range ticks {
		now += kernel.RetryMax
		must(e.k.Tick(now))
	}
	return e
}

// always draws 0 from every IntN(3): a flaky store that fails each delete.
type always struct{}

func (always) Uint64() uint64 { return 1 << 40 }

func (e *eraseRig) judge() error {
	return judgeErase(e.k, e.anchors, e.keys, e.stores, e.subs, e.gone, e.items)
}

// Each judge of the erase sim passes an honest settled erase and names each
// violation planted in what it is shown: the log, the key table, the stores,
// the items and the subjects the owner erased (CAP-3, LOG-4).
func TestTheEraseJudgesNameEachPlantedViolation(t *testing.T) {
	e := newEraseRig(t, 4, false)
	if err := e.judge(); err != nil {
		t.Fatalf("an honest erase: %v", err)
	}
	if n, err := judgePlans(e.k); err != nil || n != 2 {
		t.Fatalf("an honest erase's plans: %d cancelled, %v; want the 2 lineage-0 submitted after its read", n, err)
	}
	if err := judgeReads(e.k, e.gone, e.firsts); err != nil {
		t.Fatalf("an honest erase's reads: %v", err)
	}
	if err := newEraseRig(t, 1, true).judge(); err == nil || !strings.HasPrefix(err.Error(), "invariant: still unerased") {
		t.Errorf("an erase no store has confirmed yet: got %v", err)
	}
	for _, c := range []struct {
		name, want string
		plant      func(e *eraseRig) error
	}{
		{"a kept subject called erased", "invariant: 0 subject.erased for one erase", func(e *eraseRig) error {
			e.gone[e.subs[1]] = true
			return e.judge()
		}},
		{"an erased subject called kept", "invariant: a subject the owner kept was erased", func(e *eraseRig) error {
			e.gone = map[string]bool{}
			return e.judge()
		}},
		{"an erased subject's key back in the table", "invariant: an erased subject's key is in the table", func(e *eraseRig) error {
			e.keys.M[e.subs[0]] = e.sk
			return e.judge()
		}},
		{"a kept subject's key lost", "invariant: a kept subject lost its key", func(e *eraseRig) error {
			delete(e.keys.M, e.subs[1])
			return e.judge()
		}},
		{"a confirmed store of a subject the judge was not shown", "invariant: 1 erase.confirmed for one store", func(e *eraseRig) error {
			e.subs, e.gone = e.subs[1:], map[string]bool{}
			delete(e.items, e.hs[0])
			return e.judge()
		}},
		{"an erased subject that never was", "invariant: a store that held an erased item never confirmed", func(e *eraseRig) error {
			e.gone["ghost"] = true
			return e.judge()
		}},
		{"an erased item still stored", "invariant: an erased item is still readable or stored", func(e *eraseRig) error {
			e.mem["mail"].M[e.hs[0]] = e.ct
			return e.judge()
		}},
		{"a kept item called erased", "invariant: an erased item is still readable or stored", func(e *eraseRig) error {
			it := e.items[e.hs[1]]
			it.subject = e.subs[0]
			e.items[e.hs[1]] = it
			return e.judge()
		}},
		{"an erased item in a store that never confirmed", "invariant: a store that held an erased item never confirmed", func(e *eraseRig) error {
			it := e.items[e.hs[0]]
			it.store = "notes"
			e.items[e.hs[0]] = it
			return e.judge()
		}},
		{"a kept item that reads another text", "invariant: a kept item does not read: <nil>", func(e *eraseRig) error {
			it := e.items[e.hs[1]]
			it.text = "another"
			e.items[e.hs[1]] = it
			return e.judge()
		}},
		{"a live state the log does not give", "invariant: replay differs from the live state", func(e *eraseRig) error {
			e.k.State().Order = append(e.k.State().Order, "ghost")
			return e.judge()
		}},
		{"a read the log does not name", "invariant: erased reads", func(e *eraseRig) error {
			e.firsts[[2]string{e.subs[0], "lineage-1"}] = 1
			return judgeReads(e.k, e.gone, e.firsts)
		}},
		{"an owed plan left live", "invariant: plan lineage-0/after-0, submitted after its lineage read an erased subject, is pending", func(e *eraseRig) error {
			p := e.k.State().Plans["lineage-0/after-0"]
			p.Status, p.Cancel = kernel.SPending, ""
			_, err := judgePlans(e.k)
			return err
		}},
		{"a plan cancelled for an erase it did not follow", "invariant: plan lineage-1/early was cancelled for an erase it did not follow", func(e *eraseRig) error {
			e.k.State().Plans["lineage-1/early"].Cancel = kernel.CErased
			_, err := judgePlans(e.k)
			return err
		}},
	} {
		if err := c.plant(newEraseRig(t, 4, false)); err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}
