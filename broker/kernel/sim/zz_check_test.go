package sim

// REQ: EVL-1, KRN-1, KRN-8

import (
	"encoding/json"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The sim's per-op check reports the world's first finding, a log that does
// not replay, a replay that differs from the live state, and an effect with
// no dispatch record; an effect whose step the log dispatched passes.
func TestTheSimsCheckNamesEachPlantedViolation(t *testing.T) {
	for _, c := range []struct {
		name string
		want string // "" for none
		edit func(b *book, s *sim)
	}{
		{"an effect the log dispatched", "", func(b *book, s *sim) {
			s.w.effects = []effect{{idem: kernel.Idem("p1", 0)}}
		}},
		{"the world's first finding", "invariant: first", func(b *book, s *sim) {
			s.w.bad = []string{"first", "second"}
		}},
		{"an effect never dispatched", "invariant: an effect with no dispatch record in the log", func(b *book, s *sim) {
			s.w.effects = []effect{{idem: kernel.Idem("p1", 0)}, {idem: kernel.Idem("p1", 1)}}
		}},
		{"a live state the log does not give", "invariant: replay differs from the live state", func(b *book, s *sim) {
			s.k.State().Order = append(s.k.State().Order, "ghost")
		}},
	} {
		b := newBook(t)
		b.plan("p1", b.clerk)
		b.dispatch("p1", 0)
		s := &sim{k: b.folded(), w: &world{anchors: []key.PublicKey{b.owner.pk}}}
		c.edit(b, s)
		err := s.check()
		if c.want == "" && err != nil || c.want != "" && (err == nil || err.Error() != c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	b := newBook(t)
	b.plan("p1", b.clerk)
	b.add(kernel.TStepResult, map[string]any{"plan": "p1", "index": 0, "idem": kernel.Idem("p1", 0), "outcome": "ok"})
	s := &sim{k: b.folded(), w: &world{anchors: []key.PublicKey{b.owner.pk}, effects: []effect{{idem: kernel.Idem("p1", 0)}}}}
	if err := s.check(); err == nil || err.Error() != "invariant: an effect with no dispatch record in the log" {
		t.Errorf("an effect only a result names: got %v", err)
	}
	b = newBook(t)
	b.add(kernel.TPlanSubmit, "not a plan")
	s = &sim{k: b.booted(), w: &world{anchors: []key.PublicKey{b.owner.pk}}}
	if err := s.check(); err == nil || !strings.HasPrefix(err.Error(), "replay: ") {
		t.Errorf("a log that does not replay: got %v", err)
	}
}

// folded is the book's log as a kernel booted from it, which folds every entry.
func (b *book) folded() *kernel.Kernel {
	head := gen(rand.New(rand.NewPCG(3, 4)))
	cfg := kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{},
		Pub: head.pub, Sign: head.priv, Rand: rand.NewChaCha8([32]byte{})}
	l, err := kernel.Open(cfg)
	if err != nil {
		b.t.Fatal(err)
	}
	for _, e := range b.es {
		if _, err := l.Append(e.At, e.Type, e.V, json.RawMessage(e.Body)); err != nil {
			b.t.Fatal(err)
		}
	}
	if l, err = kernel.Open(cfg); err != nil {
		b.t.Fatal(err)
	}
	k, err := kernel.Boot(l, []key.PublicKey{b.owner.pk}, nil, 0)
	if err != nil {
		b.t.Fatal(err)
	}
	return k
}

// A caught mutant fails the run at the op whose check first saw it, with
// the seed, that op's count and the last 12 lines of the trace, so the
// failure reproduces from its seed alone (EVL-1).
func TestACaughtRunNamesItsSeedOpAndTail(t *testing.T) {
	r, err := Run(Config{Seed: 15, Ops: 200, Mutant: MutantNoDedupe})
	if err == nil {
		t.Fatal("seed 15 no longer catches the forgetful clerk")
	}
	head, tail, _ := strings.Cut(err.Error(), "\n")
	if want := "seed 15 op 16: invariant: effect twice for 5195def9"; head != want {
		t.Errorf("failed with %q, want %q", head, want)
	}
	if len(r.Trace) != 16 || tail != strings.Join(r.Trace[4:], "\n") {
		t.Errorf("tail %q, want the last 12 of %d trace lines", tail, len(r.Trace))
	}
}
