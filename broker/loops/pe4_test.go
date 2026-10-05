package loops

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// REQ: LOOP-9, RES-1, OP-8, CHG-2

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

// trail records, in order, what a pass did: containments, texts and
// proposals.
type trail struct{ got []string }

type trailContain struct {
	contain
	t *trail
}

func (c *trailContain) Contain(ctx context.Context, tg Target, id string) error {
	c.t.got = append(c.t.got, "contain "+tg.Name)
	return c.contain.Contain(ctx, tg, id)
}

// preemptingPipe answers every proposal as preempted, cancelling the
// pass's context the way the scheduler does when it preempts a job.
type preemptingPipe struct {
	*change.Pipeline
	t       *trail
	preempt context.CancelFunc
}

func (p *preemptingPipe) Propose(ctx context.Context, c change.Candidate) (change.Report, error) {
	p.t.got = append(p.t.got, "propose")
	if p.preempt != nil {
		p.preempt()
	}
	return change.Report{}, change.ErrInterrupted
}

// L3 and Security on #112: a pending fix, retried or new, is proposed only
// after every new finding is contained and the owner texted, so a
// preempted retry never leaves a new finding uncontained and unsaid.
func TestNewFindingsAreContainedBeforeAnyFixIsProposed(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	tr := &trail{}
	pl := &preemptingPipe{Pipeline: newPipe(t), t: tr}
	fx := &fixer{cand: change.Candidate{Files: change.Tree{"config/facts.json": facts("3.0.14")}}}
	g, err := NewGuard(GuardConfig{Box: b.Box(), Pipeline: pl, Store: &change.MemStore{}, Contain: &trailContain{t: tr},
		FixturesLive: true, Fixer: fx, Notify: func(string, bool) { tr.got = append(tr.got, "text") },
		Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	g.Pass(context.Background())
	if want := []string{"contain egress", "text", "propose"}; !slices.Equal(tr.got, want) {
		t.Fatalf("first pass: %q, want %q", tr.got, want)
	}
	if rec := advisoryRecord(t, g); rec.Fix != FixPreempted {
		t.Fatalf("fix %q", rec.Fix)
	}
	tr.got = nil
	b.measured["guest-image/openclaw"] = "tampered" // new, High, contained
	ctx, cancel := context.WithCancel(context.Background())
	pl.preempt = cancel
	g.Pass(ctx)
	if len(tr.got) != 3 || !strings.HasPrefix(tr.got[0], "contain ") || tr.got[1] != "text" || tr.got[2] != "propose" {
		t.Fatalf("second pass: %q, want a containment, the text, then the retried proposal", tr.got)
	}
	var hash Record
	for _, e := range g.Evidence() {
		if e.Finding.Check == CheckHash {
			hash = e
		}
	}
	if hash.Contained != "paused" || !hash.Texted {
		t.Fatalf("new finding: %+v", hash)
	}
}

// Security on #112 (CHG-2): a kept candidate is offered again only while
// the namespaces it touches are unchanged; after a newer adoption there
// the fixer builds afresh, so the kept candidate cannot revert it.
func TestAKeptFixIsRebuiltAfterANewerAdoption(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	pl := &interruptOnce{Pipeline: newPipe(t), n: 1}
	fx := &fixer{cand: change.Candidate{Files: change.Tree{"config/facts.json": facts("3.0.14")}}}
	g, err := NewGuard(GuardConfig{Box: b.Box(), Pipeline: pl, Store: &change.MemStore{}, Contain: &contain{},
		FixturesLive: true, Fixer: fx, Notify: func(string, bool) {}, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	g.Pass(context.Background()) // built, preempted, kept
	if fx.calls != 1 || advisoryRecord(t, g).Fix != FixPreempted {
		t.Fatalf("%d fixer calls, fix %q", fx.calls, advisoryRecord(t, g).Fix)
	}
	rep, err := pl.Pipeline.Propose(context.Background(), change.Candidate{Source: change.Local, Origin: "test",
		Files: change.Tree{"config/facts.json": facts("3.0.15")}})
	if err != nil || rep.State != change.StateAdopted {
		t.Fatalf("newer adoption: %+v, %v", rep, err)
	}
	g.Pass(context.Background())
	if fx.calls != 2 {
		t.Fatalf("a kept candidate was offered over a newer adoption: %d fixer calls", fx.calls)
	}
}

// failFixer fails without being preempted.
type failFixer struct{ calls int }

func (f *failFixer) Fix(context.Context, Finding) (change.Candidate, error) {
	f.calls++
	return change.Candidate{}, errors.New("no fix")
}

// L3 on #112 (OP-8): a fixer that fails, not preempted, leaves a final
// state; it is not called again on every pass.
func TestAFailedFixerIsNotRetriedEveryPass(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	fx := &failFixer{}
	g, err := NewGuard(GuardConfig{Box: b.Box(), Pipeline: newPipe(t), Store: &change.MemStore{}, Contain: &contain{},
		FixturesLive: true, Fixer: fx, Notify: func(string, bool) {}, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Pass(context.Background()); err == nil {
		t.Fatal("a failed fixer was not reported")
	}
	if rec := advisoryRecord(t, g); rec.Fix != FixFailed {
		t.Fatalf("fix %q", rec.Fix)
	}
	g.Pass(context.Background())
	g.Pass(context.Background())
	if fx.calls != 1 {
		t.Fatalf("%d fixer calls", fx.calls)
	}
}

// A kept candidate goes when its finding clears: if the finding comes
// back, the fixer builds afresh.
func TestAKeptFixIsDroppedWhenItsFindingClears(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	pl := &interruptOnce{Pipeline: newPipe(t), n: 1}
	fx := &fixer{cand: change.Candidate{Files: change.Tree{"config/facts.json": facts("3.0.14")}}}
	g, err := NewGuard(GuardConfig{Box: b.Box(), Pipeline: pl, Store: &change.MemStore{}, Contain: &contain{},
		FixturesLive: true, Fixer: fx, Notify: func(string, bool) {}, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	g.Pass(context.Background()) // kept
	b.pkgs[0].Version = "3.0.15"
	g.Pass(context.Background()) // cleared
	b.pkgs[0].Version = "3.0.13"
	g.Pass(context.Background()) // back
	if fx.calls != 2 || advisoryRecord(t, g).Fix != string(change.StateAdopted) {
		t.Fatalf("%d fixer calls, fix %q", fx.calls, advisoryRecord(t, g).Fix)
	}
}

func TestKeptFixesAreBoundedOldestFirst(t *testing.T) {
	now := t0
	g, err := NewGuard(GuardConfig{Pipeline: newPipe(t), Store: &change.MemStore{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= maxHeldFixes; i++ {
		g.keep(fmt.Sprint("f", i), heldFix{at: now})
		now = now.Add(time.Second)
	}
	if _, oldest := g.held["f0"]; len(g.held) != maxHeldFixes || oldest {
		t.Fatalf("%d kept, oldest kept: %v", len(g.held), oldest)
	}
}
