package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strconv"
	"strings"
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
// JRN-startup-reconcile s3 (Security R1 and Potency PT1 on #1382) pins
// where: counting call sites passed each mutant below, which breaks the
// FORGET take-back. Each must fail and the real source must pass.
//   - R1: the boot's resume run before daemon.Run, ahead of the gate, the
//     owner channel and the agent machine (JRN-s3-2).
//   - Q1, Q2: the recall-on or recall-off arm runs no boot resume, so an
//     interrupted item 2 is never taken back, or the owner never told
//     forgetAgentNotOpen (JRN-s3-1).
//   - Q3: wireResume given nil with recall configured: recall wired as
//     off (JRN-s3-3).
//   - Q3c: recall's OnOpen handed over outside the recall guard, so
//     recall off is wired as on (JRN-s3-3).
//   - Q3d: the same, through an unguarded var declaration (JRN-s3-3).
//
// Brief JRN-startup-reconcile-s3: JRN-s3-1..4 (subtest names).
// REQ: CAP-3, OP-4
func TestForgetResumeIsWiredOnlyThroughWireResume(t *testing.T) {
	srcs := agentosdSources(t)
	t.Run("JRN-s3-4 production wiring passes", func(t *testing.T) {
		for _, bad := range forgetResumeWiring(t, srcs) {
			t.Error(bad)
		}
	})
	runBoot := "if resumeBoot != nil {\n\t\t\tresumeBoot()\n\t\t}\n"
	for _, m := range []struct {
		name, old, new, req string
	}{
		{"R1 boot resume before daemon.Run", "\td, err := daemon.Run(ctx, cfg)\n",
			"\tif resumeBoot != nil {\n\t\tresumeBoot()\n\t}\n\td, err := daemon.Run(ctx, cfg)\n", "JRN-s3-2"},
		{"Q1 recall-on arm drops it", "\t\t" + runBoot + "\t\tgo openRecall(", "\t\tgo openRecall(", "JRN-s3-1"},
		{"Q2 recall-off arm drops it", "caps.recallWired(false)\n\t\t" + runBoot, "caps.recallWired(false)\n", "JRN-s3-1"},
		{"Q3 recall wired as off", "wireResume(ctx, onOpen)", "wireResume(ctx, nil)", "JRN-s3-3"},
		{"Q3c OnOpen outside the recall guard", "\t\tif recallDir != \"\" && verifier != nil {\n\t\t\tonOpen = recallExec.OnOpen\n\t\t}\n",
			"\t\tonOpen = recallExec.OnOpen\n", "JRN-s3-3"},
		{"Q3d OnOpen in an unguarded var declaration", "\t\tvar onOpen func(func())\n\t\tif recallDir != \"\" && verifier != nil {\n\t\t\tonOpen = recallExec.OnOpen\n\t\t}\n",
			"\t\tvar onOpen func(func()) = recallExec.OnOpen\n", "JRN-s3-3"},
	} {
		t.Run(m.req+" "+m.name+" fails", func(t *testing.T) {
			src := srcs["main.go"]
			if n := strings.Count(src, m.old); n != 1 {
				t.Fatalf("main.go holds the mutated text %d times (want 1): %q", n, m.old)
			}
			mut := make(map[string]string, len(srcs))
			for k, v := range srcs {
				mut[k] = v
			}
			mut["main.go"] = strings.Replace(src, m.old, m.new, 1)
			// The mutant breaks its own requirement and nothing else.
			bad := forgetResumeWiring(t, mut)
			own := 0
			for _, b := range bad {
				if strings.HasPrefix(b, m.req+":") {
					own++
				} else {
					t.Errorf("mutant broke more than %s: %s", m.req, b)
				}
			}
			if own == 0 {
				t.Errorf("mutant passed %s", m.req)
			}
		})
	}
}

// forgetResumeWiring parses agentosd's sources and lists each way the
// forget resume is wired wrong, each prefixed with the requirement it
// breaks.
func forgetResumeWiring(t *testing.T, srcs map[string]string) []string {
	t.Helper()
	var bad []string
	fset := token.NewFileSet()
	calls, onOpen, boots := 0, 0, 0
	var main *ast.File
	for name, src := range srcs {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		if name == "main.go" {
			main = f
		}
		for _, d := range f.Decls {
			fn, _ := d.(*ast.FuncDecl)
			inWire := fn != nil && fn.Name.Name == "wireResume"
			ast.Inspect(d, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.AssignStmt:
					for i, l := range n.Lhs {
						if s, ok := l.(*ast.SelectorExpr); ok && (s.Sel.Name == "resume" || s.Sel.Name == "whenOpen" || s.Sel.Name == "noRecall") && !inWire {
							bad = append(bad, fmt.Sprintf("wiring: %s: %s assigned outside wireResume", fset.Position(l.Pos()), s.Sel.Name))
						}
						if name != "main.go" || i >= len(n.Rhs) {
							continue
						}
						if c, ok := n.Rhs[i].(*ast.CallExpr); ok {
							if s, ok := c.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "wireResume" {
								calls++
							}
						}
					}
				case *ast.SelectorExpr:
					if name == "main.go" && isSel(n, "recallExec", "OnOpen") {
						onOpen++
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
		bad = append(bad, fmt.Sprintf("wiring: main wires the forget resume %d times (want 1), passes recall's OnOpen %d times (want 1), runs the boot's resume %d times (want some)", calls, onOpen, boots))
	}
	if main == nil {
		return append(bad, "wiring: no main.go")
	}

	// Positions in main.go of the calls the order rests on.
	var resumes, attaches, agents []token.Pos
	var wires []*ast.CallExpr
	fromOnOpen := map[string]bool{}
	var arms, guards []*ast.IfStmt
	var onOpens []*ast.SelectorExpr
	ast.Inspect(main, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "resumeBoot" {
				resumes = append(resumes, n.Pos())
			}
			if isSel(n.Fun, "lp", "attach") {
				attaches = append(attaches, n.Pos())
			}
			if s, ok := n.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Store" {
				if a, ok := s.X.(*ast.SelectorExpr); ok && a.Sel.Name == "agent" {
					if o, ok := a.X.(*ast.SelectorExpr); ok && o.Sel.Name == "forgetOwner" {
						agents = append(agents, n.Pos())
					}
				}
			}
			if s, ok := n.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "wireResume" {
				wires = append(wires, n)
			}
		case *ast.AssignStmt:
			for i, l := range n.Lhs {
				if id, ok := l.(*ast.Ident); ok && i < len(n.Rhs) && isSel(n.Rhs[i], "recallExec", "OnOpen") {
					fromOnOpen[id.Name] = true
				}
			}
		case *ast.ValueSpec:
			for i, id := range n.Names {
				if i < len(n.Values) && isSel(n.Values[i], "recallExec", "OnOpen") {
					fromOnOpen[id.Name] = true
				}
			}
		case *ast.SelectorExpr:
			if isSel(n, "recallExec", "OnOpen") {
				onOpens = append(onOpens, n)
			}
		case *ast.IfStmt:
			if types.ExprString(n.Cond) == `recallDir != "" && verifier != nil` {
				if n.Else != nil {
					arms = append(arms, n)
				}
				guards = append(guards, n)
			}
		}
		return true
	})

	// JRN-s3-1: each arm of the recall if/else runs the boot's resume.
	if len(arms) != 1 {
		bad = append(bad, fmt.Sprintf("JRN-s3-1: main.go has %d recall if/else (want 1)", len(arms)))
	}
	for _, a := range arms {
		for _, arm := range []struct {
			name string
			node ast.Node
		}{{"recall-on", a.Body}, {"recall-off", a.Else}} {
			if !callsResumeBoot(arm.node) {
				bad = append(bad, fmt.Sprintf("JRN-s3-1: %s: the %s arm runs no resumeBoot()", fset.Position(arm.node.Pos()), arm.name))
			}
		}
	}

	// JRN-s3-2: every resumeBoot() comes after lp.attach( and
	// forgetOwner.agent.Store( in source order.
	if len(attaches) == 0 || len(agents) == 0 {
		bad = append(bad, fmt.Sprintf("JRN-s3-2: main.go calls lp.attach %d times and forgetOwner.agent.Store %d times (want some of each)", len(attaches), len(agents)))
	}
	for _, r := range resumes {
		for _, p := range append(append([]token.Pos(nil), attaches...), agents...) {
			if r < p {
				bad = append(bad, fmt.Sprintf("JRN-s3-2: %s: resumeBoot() runs before %s", fset.Position(r), fset.Position(p)))
			}
		}
	}

	// JRN-s3-3: wireResume's second argument is assigned from
	// recallExec.OnOpen.
	if len(wires) != 1 {
		bad = append(bad, fmt.Sprintf("JRN-s3-3: main.go calls wireResume %d times (want 1)", len(wires)))
	}
	for _, w := range wires {
		var id *ast.Ident
		if len(w.Args) == 2 {
			id, _ = w.Args[1].(*ast.Ident)
		}
		if id == nil || !fromOnOpen[id.Name] {
			bad = append(bad, fmt.Sprintf("JRN-s3-3: %s: wireResume's second argument is not assigned from recallExec.OnOpen", fset.Position(w.Pos())))
		}
	}
	// Recall's OnOpen appears only inside the recall guard's body, in any
	// statement: unguarded, recall off would be wired as on.
	for _, a := range onOpens {
		guarded := false
		for _, g := range guards {
			if a.Pos() >= g.Body.Pos() && a.End() <= g.Body.End() {
				guarded = true
			}
		}
		if !guarded {
			bad = append(bad, fmt.Sprintf("JRN-s3-3: %s: recallExec.OnOpen outside the body of `if recallDir != \"\" && verifier != nil`", fset.Position(a.Pos())))
		}
	}
	return bad
}

// isSel reports whether e is x.sel.
func isSel(e ast.Expr, x, sel string) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok || s.Sel.Name != sel {
		return false
	}
	id, ok := s.X.(*ast.Ident)
	return ok && id.Name == x
}

// callsResumeBoot reports whether n holds a resumeBoot() call.
func callsResumeBoot(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "resumeBoot" {
				found = true
			}
		}
		return !found
	})
	return found
}

// REQ: CAP-3
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
