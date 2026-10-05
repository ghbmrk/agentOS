package loops

import (
	"context"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// REQ: LOOP-9, RES-1, OP-8

// interruptOnce answers the next n proposals as preempted (change C15),
// then passes them to the real pipeline.
type interruptOnce struct {
	*change.Pipeline
	n   int
	got int
}

func (p *interruptOnce) Propose(ctx context.Context, c change.Candidate) (change.Report, error) {
	p.got++
	if p.n > 0 {
		p.n--
		return change.Report{}, change.ErrInterrupted
	}
	return p.Pipeline.Propose(ctx, c)
}

// cutFixer is a fixer whose next cut calls are cut off by preemption: the
// scheduler cancels the pass's context (preempt) while it runs.
type cutFixer struct {
	fixer
	cut     int
	preempt context.CancelFunc
}

func (f *cutFixer) Fix(ctx context.Context, fd Finding) (change.Candidate, error) {
	if f.cut > 0 {
		f.cut--
		f.calls++
		f.preempt()
		return change.Candidate{}, ctx.Err()
	}
	return f.fixer.Fix(ctx, fd)
}

func advisoryRecord(t *testing.T, g *Guard) Record {
	t.Helper()
	for _, e := range g.Evidence() {
		if e.Finding.Check == CheckAdvisory {
			g.mu.Lock()
			rec := g.st.Open[e.Finding.ID]
			g.mu.Unlock()
			return rec
		}
	}
	t.Fatal("no advisory finding")
	return Record{}
}

// PE4 (L3 on #103): a Loop 2 fix whose evaluation was preempted is not
// recorded as an empty fix and dropped. It stays pending, and the next
// pass offers the fixer's checked candidate again without another fixer
// call; after a restart, or once the kept candidate is older than
// change.ResumeFor, the fixer is asked afresh. A fixer cut off by
// preemption leaves the fix pending too.
func TestAPreemptedFixIsOfferedAgain(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	now := t0
	pl := &interruptOnce{Pipeline: newPipe(t), n: 1}
	fx := &cutFixer{fixer: fixer{cand: change.Candidate{Files: change.Tree{"config/facts.json": facts("3.0.14")}}}}
	store := &change.MemStore{}
	open := func() *Guard {
		g, err := NewGuard(GuardConfig{Box: b.Box(), Pipeline: pl, Store: store, Contain: &contain{}, FixturesLive: true,
			Fixer: fx, Notify: func(string, bool) {}, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	g := open()
	if _, err := g.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec := advisoryRecord(t, g); rec.Fix != FixPreempted {
		t.Fatalf("a preempted fix was recorded as %q", rec.Fix)
	}
	if _, err := g.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := advisoryRecord(t, g)
	if rec.Fix != string(change.StateAdopted) || fx.calls != 1 || pl.got != 2 {
		t.Fatalf("after the next pass: fix %q (%s), %d fixer calls, %d proposals", rec.Fix, rec.FixReason, fx.calls, pl.got)
	}
	if ev := g.Evidence(); len(ev) != 1 || ev[0].Fix != string(change.StateAdopted) || ev[0].Seen != 1 {
		t.Fatalf("evidence: %+v", ev)
	}
	if _, err := g.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fx.calls != 1 || pl.got != 2 {
		t.Fatalf("a settled fix was proposed again: %d calls, %d proposals", fx.calls, pl.got)
	}
}

func TestAPreemptedFixIsRebuiltAfterARestartOrExpiry(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	now := t0
	pl := &interruptOnce{Pipeline: newPipe(t), n: 2}
	fx := &cutFixer{fixer: fixer{cand: change.Candidate{Files: change.Tree{"config/facts.json": facts("3.0.14")}}}, cut: 1}
	store := &change.MemStore{}
	open := func() *Guard {
		g, err := NewGuard(GuardConfig{Box: b.Box(), Pipeline: pl, Store: store, Contain: &contain{}, FixturesLive: true,
			Fixer: fx, Notify: func(string, bool) {}, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	g := open()
	ctx, cancel := context.WithCancel(context.Background())
	fx.preempt = cancel
	g.Pass(ctx) // the fixer is cut off
	if rec := advisoryRecord(t, g); rec.Fix != FixPreempted || pl.got != 0 {
		t.Fatalf("a cut-off fixer: fix %q, %d proposals", rec.Fix, pl.got)
	}
	g.Pass(context.Background()) // built, proposal preempted, kept
	if fx.calls != 2 || pl.got != 1 {
		t.Fatalf("%d fixer calls, %d proposals", fx.calls, pl.got)
	}
	g = open() // a restart drops the kept candidate; the pending fix stays
	g.Pass(context.Background())
	if fx.calls != 3 || pl.got != 2 {
		t.Fatalf("after a restart: %d fixer calls, %d proposals", fx.calls, pl.got)
	}
	now = now.Add(change.ResumeFor + time.Minute) // kept, but too old
	g.Pass(context.Background())
	if rec := advisoryRecord(t, g); rec.Fix != string(change.StateAdopted) || fx.calls != 4 {
		t.Fatalf("after expiry: fix %q, %d fixer calls", rec.Fix, fx.calls)
	}
}
