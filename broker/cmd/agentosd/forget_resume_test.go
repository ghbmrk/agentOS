package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/recalltool"
)

// fakeRecallOpen stands in for recall's LateExecutor.OnOpen: callbacks
// wait for open, and one registered after it runs at once.
type fakeRecallOpen struct {
	mu      sync.Mutex
	open    bool
	pending []func()
}

func (o *fakeRecallOpen) OnOpen(f func()) {
	o.mu.Lock()
	if !o.open {
		o.pending = append(o.pending, f)
		o.mu.Unlock()
		return
	}
	o.mu.Unlock()
	f()
}

func (o *fakeRecallOpen) Open() {
	o.mu.Lock()
	o.open = true
	fs := o.pending
	o.pending = nil
	o.mu.Unlock()
	for _, f := range fs {
		f()
	}
}

func (r *forgetRig) told() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.texts...)
}

func (w *fakeWork) backCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.backs)
}

// REQ: CAP-3, OP-4, CH-12
// #1370 and Security S1 on #1382: the resume wireResume sets up runs an
// interrupted item 2 once, at the right time, whichever comes first,
// startup reconcile finding it or the boot's resume. Startup reconcile
// runs inside daemon.Run, before boot setup has attached the gate, the
// owner channel and the agent machine ("early"); or after boot, once
// recall has opened and its resume found nothing ("late").
//   - Recall off: the owner is told once that it cannot be done
//     (forgetAgentNotOpen). Early, the run waits for the boot's resume:
//     run before it, it would tell "item 2 goes only with item 1" (no
//     gate) or promise a later take-back (no agent), and drain the queue.
//   - Recall on: the agent is taken back once and told done.
//
// With no agent machine (JRN-startup-reconcile s5, Security R3 on #1382),
// recall off still tells forgetAgentNotOpen: a take-back "when it runs
// again" cannot happen with recall off, even once the agent runs. Recall
// on keeps that promise (forgetAgentNoAgent), since the agent's next run
// can be taken back.
func TestForgetItem2ResumeWaitsForBootSetup(t *testing.T) {
	for _, c := range []struct {
		name    string
		recall  bool
		early   bool
		noAgent bool
		want    string
		backs   int
	}{
		{"recall off, reconciled before boot setup", false, true, false, forgetAgentNotOpen, 0},
		{"recall off, reconciled after boot", false, false, false, forgetAgentNotOpen, 0},
		{"recall on, reconciled before boot setup", true, true, false, forgetAgentDone, 1},
		{"recall on, reconciled after recall opened", true, false, false, forgetAgentDone, 1},
		{"recall off, no agent, reconciled before boot setup", false, true, true, forgetAgentNotOpen, 0},
		{"recall off, no agent, reconciled after boot", false, false, true, forgetAgentNotOpen, 0},
		{"recall on, no agent, reconciled before boot setup", true, true, true, forgetAgentNoAgent, 0},
		{"recall on, no agent, reconciled after recall opened", true, false, true, forgetAgentNoAgent, 0},
	} {
		r := newForgetRig(t)
		w := &fakeWork{worked: true, ok: true}
		if !c.recall {
			w.err = recalltool.ErrNotOpen
		}
		r.withAgent(w)
		r.task("owner:a", "pay the gas bill", r.now.Add(-time.Hour), viaSMS)
		r.say("FORGET LAST")
		r.gate.st = map[string]journal.State{r.gate.got[0].ID: journal.Succeeded}
		item2 := r.gate.got[1]
		r.texts = nil
		// A restart: nothing of boot setup is attached yet.
		gate := r.f.gate.Load()
		r.f.gate.Store(nil)
		r.f.agent.Store(nil)
		ctx, cancel := context.WithCancel(context.Background())
		var onOpen func(func())
		rec := &fakeRecallOpen{}
		if c.recall {
			onOpen = rec.OnOpen
		}
		boot := r.f.wireResume(ctx, onOpen)
		setup := func() {
			r.f.gate.Store(gate)
			if !c.noAgent {
				r.withAgent(w)
			}
			boot()
			if c.recall {
				rec.Open()
			}
		}
		if c.early {
			r.f.Reconcile(ctx, item2, 1)
			// Give a resume that does not wait the time to tell.
			for end := time.Now().Add(300 * time.Millisecond); time.Now().Before(end) && len(r.told()) == 0; {
				time.Sleep(5 * time.Millisecond)
			}
			if got := r.told(); len(got) != 0 {
				t.Fatalf("%s: told %q before boot setup", c.name, got)
			}
			setup()
		} else {
			setup()
			// The boot's resume has run and found nothing queued.
			waitIdle(r.f)
			r.f.Reconcile(ctx, item2, 1)
		}
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end) && len(r.told()) == 0; {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		waitIdle(r.f)
		if got := r.told(); len(got) != 1 || got[0] != c.want || w.backCount() != c.backs {
			t.Errorf("%s: took back %d, told %q; want %d and %q once", c.name, w.backCount(), got, c.backs, c.want)
		}
		cancel()
	}
}

// waitIdle waits for any resumeAgent run in progress to finish.
func waitIdle(f *ownerForget) {
	time.Sleep(20 * time.Millisecond)
	f.resuming.Lock()
	f.resuming.Unlock() //nolint:staticcheck // a barrier, not a section
}

// The resume is wired in one place: nothing in agentosd assigns an
// ownerForget's resume, whenOpen or noRecall but wireResume, and main wires through
// it once, with recall's OnOpen, and runs the boot's resume it returns
// (PT1 and S3 on #1382: dropping the wiring passed every other test).
// REQ: CAP-3, OP-4
func TestForgetResumeIsWiredOnlyThroughWireResume(t *testing.T) {
	fset := token.NewFileSet()
	calls, onOpen, boots := 0, 0, 0
	for name, src := range agentosdSources(t) {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, _ := d.(*ast.FuncDecl)
			inWire := fn != nil && fn.Name.Name == "wireResume"
			ast.Inspect(d, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					for i, l := range n.Lhs {
						if s, ok := l.(*ast.SelectorExpr); ok && (s.Sel.Name == "resume" || s.Sel.Name == "whenOpen" || s.Sel.Name == "noRecall") && !inWire {
							t.Errorf("%s: %s assigned outside wireResume", fset.Position(l.Pos()), s.Sel.Name)
						}
						if name != "main.go" || i >= len(n.Rhs) {
							continue
						}
						if s, ok := n.Rhs[i].(*ast.SelectorExpr); ok && s.Sel.Name == "OnOpen" {
							if x, ok := s.X.(*ast.Ident); ok && x.Name == "recallExec" {
								onOpen++
							}
						}
						if c, ok := n.Rhs[i].(*ast.CallExpr); ok {
							if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "wireResume" {
								calls++
							}
						}
					}
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "resumeBoot" && name == "main.go" {
						boots++
					}
				}
				return true
			})
		}
	}
	if calls != 1 || onOpen != 1 || boots == 0 {
		t.Errorf("main wires the forget resume %d times (want 1), passes recall's OnOpen %d times (want 1), runs the boot's resume %d times (want some)", calls, onOpen, boots)
	}
}

// REQ: RCH-4, CAP-3
// JRN-startup-reconcile s4 (Security R2 on #1382): with recall on and
// startup reconcile queueing nothing, the boot resume wireResume returns
// is the only run on recall's open. It takes back an item 2 an earlier
// boot left that the journal still holds, takes back a restored forget
// log's take-back, and tells an owed done text recall now holds done.
// Nothing runs before recall opens. A no-op boot resume fails each case.
func TestForgetBootResumeRecallOnWithoutReconcile(t *testing.T) {
	since := time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name  string
		rig   func(*fakeWork) *forgetRig
		backs int
	}{
		{"journal-held item 2", func(w *fakeWork) *forgetRig {
			r := newForgetRig(t)
			r.withAgent(w)
			r.task("owner:a", "pay the gas bill", since, viaSMS)
			r.say("FORGET LAST")
			r.gate.st = map[string]journal.State{r.gate.got[0].ID: journal.Succeeded, r.gate.got[1].ID: journal.Succeeded}
			return r
		}, 1},
		{"restored take-back", func(w *fakeWork) *forgetRig {
			return restoredRig(t, w, &countStore{}, since)
		}, 1},
		{"owed done text", func(w *fakeWork) *forgetRig {
			r := restartRig(t, &change.MemStore{})
			r.withAgent(w)
			id := grants.ForgetAgentID("boot.1."+strconv.FormatInt(since.UnixNano(), 10), "owner:a")
			if err := r.f.owed.owe(id, owedForget{Since: since, Agent: true, Taking: true}); err != nil {
				t.Fatal(err)
			}
			w.setState(since, recalltool.TakeBackDone)
			return r
		}, 0},
	} {
		w := &fakeWork{worked: true, ok: true}
		r := c.rig(w)
		r.mu.Lock()
		r.texts = nil
		r.mu.Unlock()
		// A restart: nothing of boot setup is attached yet.
		gate, agent := r.f.gate.Load(), r.f.agent.Load()
		r.f.gate.Store(nil)
		r.f.agent.Store(nil)
		ctx, cancel := context.WithCancel(context.Background())
		rec := &fakeRecallOpen{}
		boot := r.f.wireResume(ctx, rec.OnOpen)
		r.f.gate.Store(gate)
		r.f.agent.Store(agent)
		boot()
		time.Sleep(50 * time.Millisecond)
		waitIdle(r.f)
		if got := r.told(); len(got) != 0 || w.backCount() != 0 {
			t.Fatalf("%s: before recall opened: took back %d, told %q", c.name, w.backCount(), got)
		}
		rec.Open()
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end) && len(r.told()) == 0; {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		waitIdle(r.f)
		if got := r.told(); len(got) != 1 || got[0] != forgetAgentDone || w.backCount() != c.backs {
			t.Errorf("%s: took back %d, told %q; want %d and %q once", c.name, w.backCount(), got, c.backs, forgetAgentDone)
		}
		cancel()
	}
}
