package loops

// REQ: LOOP-9, RES-1

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// cutPipeline interrupts the first cuts proposals, as when the scheduler
// preempts the evaluation, and passes the rest to the real pipeline.
type cutPipeline struct {
	*change.Pipeline
	cuts int
	got  []change.Candidate
}

func (p *cutPipeline) Propose(ctx context.Context, c change.Candidate) (change.Report, error) {
	p.got = append(p.got, c)
	if p.cuts > 0 {
		p.cuts--
		return change.Report{}, change.ErrInterrupted
	}
	return p.Pipeline.Propose(ctx, c)
}

func newCutRig(t *testing.T, cuts int) (*guardRig, *cutPipeline) {
	t.Helper()
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	r := newGuardRig(t, b)
	cp := &cutPipeline{Pipeline: r.p, cuts: cuts}
	r.pipe = cp
	r.fx = &fixer{cand: change.Candidate{Files: change.Tree{"config/facts.json": facts("3.0.14")}}}
	r.reopen(t)
	return r, cp
}

// interruptedPass runs a pass that must end interrupted, not failed.
func (r *guardRig) interruptedPass(t *testing.T) int {
	t.Helper()
	n, err := r.g.Pass(context.Background())
	if !errors.Is(err, change.ErrInterrupted) {
		t.Fatalf("pass error %v, want one wrapping change.ErrInterrupted", err)
	}
	return n
}

func advisory(t *testing.T, g *Guard) (open, evidence Record) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, rec := range g.st.Open {
		if rec.Finding.Check == CheckAdvisory {
			open = rec
		}
	}
	for _, rec := range g.st.Evidence {
		if rec.Finding.Check == CheckAdvisory {
			evidence = rec
		}
	}
	if open.Finding.ID == "" || evidence.Finding.ID == "" {
		t.Fatalf("no advisory finding: open %+v, evidence %+v", g.st.Open, g.st.Evidence)
	}
	return open, evidence
}

// PE4 (L3 on #103): a fix whose evaluation is preempted is pending, not
// recorded as an empty fix. The pass reports the interruption, so the
// scheduler counts it as preempted; the next pass offers the same
// candidate again without asking the fixer for another, and the owner is
// not texted twice.
func TestAPreemptedFixIsOfferedAgain(t *testing.T) {
	r, cp := newCutRig(t, 1)
	if n := r.interruptedPass(t); n != 1 {
		t.Fatalf("findings = %d, want 1", n)
	}
	open, ev := advisory(t, r.g)
	if open.Fix != FixPending || ev.Fix != FixPending {
		t.Fatalf("fix state open %q evidence %q, want %q", open.Fix, ev.Fix, FixPending)
	}
	if _, due := r.g.Next(context.Background(), false); !due {
		t.Fatal("a pending fix does not make the next pass due")
	}
	r.now = r.now.Add(time.Minute)
	if n := r.pass(t); n != 0 {
		t.Fatalf("second pass: %d new findings, want 0", n)
	}
	open, ev = advisory(t, r.g)
	if open.Fix != string(change.StateAdopted) || ev.Fix != string(change.StateAdopted) {
		t.Fatalf("fix state open %q evidence %q (%s), want adopted", open.Fix, ev.Fix, open.FixReason)
	}
	if r.fx.calls != 1 || len(cp.got) != 2 || change.Tree(cp.got[1].Files).Hash() != change.Tree(cp.got[0].Files).Hash() {
		t.Fatalf("fixer calls %d, proposals %d: the kept candidate was not reused", r.fx.calls, len(cp.got))
	}
	if c := cp.got[1]; c.Source != change.Local || c.Origin != "loop2" || c.Public {
		t.Fatalf("reused candidate lost Loop 2's marks: %+v", c)
	}
	if len(r.texts) != 1 || len(r.c.got) != 1 {
		t.Fatalf("texts %d, containments %d: the finding was handled twice", len(r.texts), len(r.c.got))
	}
	// Done: nothing pending, so no early pass.
	if _, due := r.g.Next(context.Background(), false); due {
		t.Fatal("a pass is due with nothing pending")
	}
}

// PE4: the kept candidate is memory only and lasts change.ResumeFor. After
// a restart, or once it is older, the fixer is asked again; a finding
// that clears while its fix is pending is not retried.
func TestAPendingFixAfterRestartOrExpiryAsksTheFixer(t *testing.T) {
	r, cp := newCutRig(t, 1)
	r.interruptedPass(t)
	r.reopen(t) // restart: the pending state is saved, the candidate is not
	r.pass(t)
	if open, _ := advisory(t, r.g); open.Fix != string(change.StateAdopted) || r.fx.calls != 2 {
		t.Fatalf("after restart: fix %q, fixer calls %d, want adopted and 2", open.Fix, r.fx.calls)
	}

	r, cp = newCutRig(t, 1)
	r.interruptedPass(t)
	r.now = r.now.Add(change.ResumeFor + time.Minute)
	r.pass(t)
	if r.fx.calls != 2 || len(cp.got) != 2 {
		t.Fatalf("after expiry: fixer calls %d, proposals %d, want 2 and 2", r.fx.calls, len(cp.got))
	}

	r, cp = newCutRig(t, 1)
	r.interruptedPass(t)
	r.b.pkgs[0].Version = "3.0.14" // fixed by an update meanwhile
	r.pass(t)
	if r.fx.calls != 1 || len(cp.got) != 1 || len(r.g.fixes) != 0 {
		t.Fatalf("cleared finding retried: fixer calls %d, proposals %d, kept %d", r.fx.calls, len(cp.got), len(r.g.fixes))
	}
}

// PE4: a fixer cut short by the pass's context ending is pending too; a
// fixer that fails on its own is an error, as before, and not retried.
func TestAFixerCutShortIsPending(t *testing.T) {
	r, _ := newCutRig(t, 0)
	ctx, cancel := context.WithCancel(context.Background())
	r.fx.err = func(context.Context) error { cancel(); return context.Canceled }
	if _, err := r.g.Pass(ctx); !errors.Is(err, change.ErrInterrupted) {
		t.Fatalf("pass error %v, want ErrInterrupted", err)
	}
	if open, _ := advisory(t, r.g); open.Fix != FixPending {
		t.Fatalf("fix %q, want pending", open.Fix)
	}
	r.fx.err = nil
	r.pass(t)
	if open, _ := advisory(t, r.g); open.Fix != string(change.StateAdopted) {
		t.Fatalf("retry: fix %q, want adopted", open.Fix)
	}

	r, _ = newCutRig(t, 0)
	r.fx.err = func(context.Context) error { return errors.New("model said no") }
	if _, err := r.g.Pass(context.Background()); err == nil || errors.Is(err, change.ErrInterrupted) {
		t.Fatalf("pass error %v, want a plain failure", err)
	}
	if open, _ := advisory(t, r.g); open.Fix == FixPending {
		t.Fatal("a failed fixer is pending")
	}
	r.fx.err = nil
	r.pass(t)
	if r.fx.calls != 1 {
		t.Fatalf("failed fixer retried: %d calls", r.fx.calls)
	}
}

// PE4: kept fix candidates are bounded, oldest dropped first.
func TestKeptFixesAreBounded(t *testing.T) {
	g := &Guard{cfg: GuardConfig{Now: func() time.Time { return t0 }}}
	for i := 0; i < maxKeptFixes+3; i++ {
		f := Finding{ID: string(rune('a' + i))}
		g.keepFix(f, change.Candidate{}, t0.Add(time.Duration(i)*time.Second))
	}
	if len(g.fixes) != maxKeptFixes {
		t.Fatalf("kept %d, want %d", len(g.fixes), maxKeptFixes)
	}
	if _, ok := g.fixes["a"]; ok {
		t.Fatal("oldest kept fix was not dropped")
	}
}
