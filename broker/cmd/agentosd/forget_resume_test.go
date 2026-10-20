package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
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
//   - Q3b: the OnOpen value overwritten before wireResume (JRN-s3-3).
//   - Q3e..Q3j: recall's OnOpen reached outside the guard through an alias,
//     a parenthesised receiver or a method expression, or inside it only
//     through a shadowed recallExec, a dead branch or an uncalled closure
//     (JRN-s3-3, #2507). JRN-s3-3 checks by go/types object, not spelling.
//   - Q3k: recallExec reassigned in the guard, so OnOpen is a fresh
//     executor's, not recall's (JRN-s3-3).
//   - Q3l..Q3n: the guard's recallDir or verifier shadowed, so recall off
//     is wired as on (JRN-s3-3). The guard is matched by go/types object.
//   - R2..R7: lp.attach or forgetOwner.agent.Store run in a goroutine, a
//     deferred or uncalled closure or a dead branch, so the boot's resume
//     can run before the owner channel or the agent is attached
//     (JRN-s3-2); R8: the recall-on arm's resumeBoot() in an uncalled
//     closure (JRN-s3-1). Each call must be a statement reached from
//     main's body only through blocks and if arms with no constant in
//     their condition.
//   - P1..P6: recallDir set before the guard, directly or through its
//     address, verifier or lp reassigned, resumeBoot reset before
//     daemon.Run or shadowed in the recall-on arm (JRN-s3-1..3). One rule
//     covers them: each object the checks rest on (recallDir, verifier,
//     recallExec, onOpen, lp, resumeBoot) is declared once in main and
//     written once, from its source; its address is taken only as that
//     write (flag.StringVar(&recallDir, ...)).
//   - K: resumeBoot run through a copy before daemon.Run (JRN-s3-2); J..J4,
//     M: wireResume called on another owner, through a copy of lp, of
//     lp.forgetOwner or of the method, or lp.forgetOwner replaced first,
//     so the daemon's own owner is never wired (JRN-s3-1). A value the
//     checks follow by object is never copied: resumeBoot is only called
//     or compared with nil, lp.forgetOwner only selected from, wireResume
//     only called, and resumeBoot's one write is a call of wireResume on
//     exactly lp.forgetOwner, lp being the pinned object. lp.attach and
//     forgetOwner.agent.Store are matched by method and field object, so a
//     copy of lp cannot hide one.
//   - F1, F2: a goto past lp.attach, or a return between the wireResume
//     call and lp.attach (each JRN-s3 it skips). main may hold no goto or
//     label, and no return between the wireResume call and a call it
//     vouches for.
//
// Out of reach, since ruling it out needs data-flow analysis: a condition
// false only at run time (x := false; if x { ... }), and leaving main
// through log.Fatal, os.Exit or panic, or blocking forever (select {}),
// before a call it vouches for. Later: flag.Set("recall", ...) writes
// recallDir with no assignment or address, consistently for the guard,
// the arms and the recall config.
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
	wire := "\t\tresumeBoot = lp.forgetOwner.wireResume(ctx, onOpen)\n"
	guarded := "\t\t\tonOpen = recallExec.OnOpen\n"
	attach := "\t\tlp.attach(ctx, d)\n"
	store := "\t\t\t\tlp.forgetOwner.agent.Store(&forgetAgent{work: recallExec,\n\t\t\t\t\tlineage: func() (string, error) { return machines{m}.Lineage(agentMachine) }})\n"
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
		{"Q3b OnOpen overwritten before wireResume", wire, "\t\tonOpen = nil\n" + wire, "JRN-s3-3"},
		{"Q3e OnOpen through a receiver alias outside the guard", wire, "\t\tre := recallExec\n\t\tonOpen = re.OnOpen\n" + wire, "JRN-s3-3"},
		{"Q3f OnOpen through a parenthesised receiver outside the guard", wire, "\t\tonOpen = (recallExec).OnOpen\n" + wire, "JRN-s3-3"},
		{"Q3g OnOpen as a method expression outside the guard", wire, "\t\t(*recalltool.LateExecutor).OnOpen(recallExec, func() {})\n" + wire, "JRN-s3-3"},
		{"Q3h OnOpen of a shadowed recallExec", guarded, "\t\t\trecallExec := &recalltool.LateExecutor{}\n" + guarded, "JRN-s3-3"},
		{"Q3i OnOpen in a dead branch", guarded, "\t\t\tif false {\n\t" + guarded + "\t\t\t}\n", "JRN-s3-3"},
		{"Q3j OnOpen in an uncalled closure", guarded, "\t\t\t_ = func() { onOpen = recallExec.OnOpen }\n", "JRN-s3-3"},
		{"Q3k recallExec reassigned in the guard", guarded, "\t\t\trecallExec = &recalltool.LateExecutor{}\n" + guarded, "JRN-s3-3"},
		{"Q3l recallDir shadowed in the guard's init", "\t\tif recallDir != \"\" && verifier != nil {\n" + guarded,
			"\t\tif recallDir := \"on\"; recallDir != \"\" && verifier != nil {\n" + guarded, "JRN-s3-3"},
		{"Q3m recallDir shadowed before the guard", "\t\tif recallDir != \"\" && verifier != nil {\n" + guarded,
			"\t\trecallDir := \"on\"\n\t\tif recallDir != \"\" && verifier != nil {\n" + guarded, "JRN-s3-3"},
		{"Q3n verifier shadowed before the guard", "\t\tif recallDir != \"\" && verifier != nil {\n" + guarded,
			"\t\tverifier := verifier\n\t\tif recallDir != \"\" && verifier != nil {\n" + guarded, "JRN-s3-3"},
		{"R2 lp.attach in its own goroutine", attach, "\t\tgo lp.attach(ctx, d)\n", "JRN-s3-2"},
		{"R3 lp.attach in a goroutine's closure", attach, "\t\tgo func() { lp.attach(ctx, d) }()\n", "JRN-s3-2"},
		{"R4 lp.attach in a deferred closure", attach, "\t\tdefer func() { lp.attach(ctx, d) }()\n", "JRN-s3-2"},
		{"R5 lp.attach in an uncalled closure", attach, "\t\t_ = func() { lp.attach(ctx, d) }\n", "JRN-s3-2"},
		{"R6 lp.attach in a dead branch", attach, "\t\tif false {\n\t" + attach + "\t\t}\n", "JRN-s3-2"},
		{"R7 forgetOwner.agent.Store in a goroutine's closure", store, "\t\t\t\tgo func() {\n" + store + "\t\t\t\t}()\n", "JRN-s3-2"},
		{"R8 recall-on resumeBoot in an uncalled closure", "\t\t" + runBoot + "\t\tgo openRecall(",
			"\t\t_ = func() { resumeBoot() }\n\t\tgo openRecall(", "JRN-s3-1"},
		{"P1 recallDir set before the guard", "\t\tif recallDir != \"\" && verifier != nil {\n" + guarded,
			"\t\trecallDir = \"on\"\n\t\tif recallDir != \"\" && verifier != nil {\n" + guarded, "JRN-s3-3"},
		{"P2 recallDir set through its address", "\t\tif recallDir != \"\" && verifier != nil {\n" + guarded,
			"\t\tp := &recallDir\n\t\t*p = \"on\"\n\t\tif recallDir != \"\" && verifier != nil {\n" + guarded, "JRN-s3-3"},
		{"P3 verifier reassigned", wire, "\t\tverifier = nil\n" + wire, "JRN-s3-3"},
		{"P4 lp reassigned", attach, "\t\tlp = nil\n" + attach, "JRN-s3-2"},
		{"P5 resumeBoot reset before daemon.Run", "\td, err := daemon.Run(ctx, cfg)\n",
			"\tresumeBoot = nil\n\td, err := daemon.Run(ctx, cfg)\n", "JRN-s3-1"},
		{"P6 resumeBoot shadowed in the recall-on arm", "\t\t" + runBoot + "\t\tgo openRecall(",
			"\t\tresumeBoot := func() {}\n\t\t" + runBoot + "\t\tgo openRecall(", "JRN-s3-1"},
		{"F1 goto past lp.attach", attach, "\t\tgoto attached\n" + attach + "\tattached:\n", "JRN-s3-1 JRN-s3-2 JRN-s3-3"},
		{"F2 return before lp.attach", attach, "\t\tif ctx.Err() != nil {\n\t\t\treturn\n\t\t}\n" + attach, "JRN-s3-1 JRN-s3-2"},
		{"K resumeBoot run through a copy before daemon.Run", "\td, err := daemon.Run(ctx, cfg)\n",
			"\trb := resumeBoot\n\trb()\n\td, err := daemon.Run(ctx, cfg)\n", "JRN-s3-2"},
		{"J wireResume on another owner", wire, "\t\tresumeBoot = new(ownerForget).wireResume(ctx, onOpen)\n", "JRN-s3-1"},
		{"J2 wireResume through a copy of lp", wire, "\t\tl := lp\n\t\tresumeBoot = l.forgetOwner.wireResume(ctx, onOpen)\n", "JRN-s3-1"},
		{"J3 wireResume through a copy of lp.forgetOwner", wire, "\t\tfo := lp.forgetOwner\n\t\tresumeBoot = fo.wireResume(ctx, onOpen)\n", "JRN-s3-1"},
		{"J4 wireResume taken as a method value", wire, "\t\t_ = lp.forgetOwner.wireResume\n" + wire, "JRN-s3-1"},
		{"M lp.forgetOwner replaced before the wire", wire, "\t\tlp.forgetOwner = new(ownerForget)\n" + wire, "JRN-s3-1"},
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
			// The mutant breaks each of its own requirements and
			// nothing else.
			reqs := strings.Fields(m.req)
			broke := map[string]bool{}
			for _, b := range forgetResumeWiring(t, mut) {
				own := false
				for _, r := range reqs {
					if strings.HasPrefix(b, r+":") {
						broke[r], own = true, true
					}
				}
				if !own {
					t.Errorf("mutant broke more than %s: %s", m.req, b)
				}
			}
			for _, r := range reqs {
				if !broke[r] {
					t.Errorf("mutant passed %s", r)
				}
			}
		})
	}
}

// forgetResumeWiring parses agentosd's sources, type-checks the ones this
// build compiles, and lists each way the forget resume is wired wrong,
// each prefixed with the requirement it breaks.
func forgetResumeWiring(t *testing.T, srcs map[string]string) []string {
	t.Helper()
	tc := agentosdTypes(t)
	var bad []string
	fset := token.NewFileSet()
	calls, boots := 0, 0
	var main *ast.File
	var files []*ast.File
	for name, src := range srcs {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		if name == "main.go" {
			main = f
		}
		if tc.goFiles[name] {
			files = append(files, f)
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
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "resumeBoot" && name == "main.go" {
						boots++
					}
				}
				return true
			})
		}
	}
	if calls != 1 || boots == 0 {
		bad = append(bad, fmt.Sprintf("wiring: main wires the forget resume %d times (want 1), runs the boot's resume %d times (want some)", calls, boots))
	}
	if main == nil {
		return append(bad, "wiring: no main.go")
	}
	if len(files) != len(tc.goFiles) {
		t.Fatalf("type-check: %d of the build's %d files given", len(files), len(tc.goFiles))
	}
	info := &types.Info{
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
		Types:      map[ast.Expr]types.TypeAndValue{},
		Scopes:     map[ast.Node]*types.Scope{},
	}
	// Soft errors (a variable declared and not used, as in Q3) still
	// leave info whole; anything else is a mutant that does not parse as Go.
	conf := types.Config{Importer: tc.imp, Error: func(err error) {
		if te, ok := err.(types.Error); !ok || !te.Soft {
			t.Fatalf("type-check: %v", err)
		}
	}}
	pkg, _ := conf.Check(tc.path, fset, files, info)
	inMain := func(n ast.Node) bool { return n.Pos() >= main.Pos() && n.End() <= main.End() }
	var mainFn *ast.FuncDecl
	for _, d := range main.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "main" {
			mainFn = fn
		}
	}
	if mainFn == nil || mainFn.Body == nil {
		return append(bad, "wiring: main.go has no func main")
	}
	parent := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(main, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if len(stack) > 0 {
			parent[n] = stack[len(stack)-1]
		}
		stack = append(stack, n)
		return true
	})
	// Each object the checks below rest on is pinned, and they match it
	// by object, not by name.
	var lateExec, onOpenFn, wireFn types.Object
	for _, p := range pkg.Imports() {
		if p.Path() == "github.com/ghbmrk/agentos/broker/recalltool" {
			if lateExec = p.Scope().Lookup("LateExecutor"); lateExec != nil {
				onOpenFn, _, _ = types.LookupFieldOrMethod(types.NewPointer(lateExec.Type()), false, p, "OnOpen")
			}
		}
	}
	var ownerField, attachFn, agentField types.Object
	if of := pkg.Scope().Lookup("ownerForget"); of != nil {
		wireFn, _, _ = types.LookupFieldOrMethod(types.NewPointer(of.Type()), false, pkg, "wireResume")
		agentField, _, _ = types.LookupFieldOrMethod(types.NewPointer(of.Type()), false, pkg, "agent")
	}
	if l := pkg.Scope().Lookup("learning"); l != nil {
		ownerField, _, _ = types.LookupFieldOrMethod(types.NewPointer(l.Type()), false, pkg, "forgetOwner")
		attachFn, _, _ = types.LookupFieldOrMethod(types.NewPointer(l.Type()), false, pkg, "attach")
	}
	if onOpenFn == nil || wireFn == nil || agentField == nil || ownerField == nil || attachFn == nil {
		return append(bad, "wiring: no recalltool.LateExecutor.OnOpen, ownerForget.wireResume or .agent, or learning.forgetOwner or .attach")
	}
	callsTo := func(e ast.Expr, pkgPath, name string) bool {
		f, _ := callee(info, e).(*types.Func)
		return f != nil && f.Pkg() != nil && f.Pkg().Path() == pkgPath && f.Name() == name
	}
	obj := map[string]types.Object{}
	for _, p := range []struct {
		name, req, src string
		from           func(ast.Expr) bool
	}{
		{"recallDir", "JRN-s3-3", "flag.StringVar", func(e ast.Expr) bool { return callsTo(e, "flag", "StringVar") }},
		{"verifier", "JRN-s3-3", "modelroute.NewVerifier", func(e ast.Expr) bool {
			return callsTo(e, "github.com/ghbmrk/agentos/broker/modelroute", "NewVerifier")
		}},
		{"recallExec", "JRN-s3-3", "&recalltool.LateExecutor{}", func(e ast.Expr) bool {
			u, ok := e.(*ast.UnaryExpr)
			if !ok || u.Op != token.AND {
				return false
			}
			c, ok := u.X.(*ast.CompositeLit)
			return ok && len(c.Elts) == 0 && types.Identical(info.TypeOf(c), lateExec.Type())
		}},
		{"onOpen", "JRN-s3-3", "recallExec.OnOpen", func(e ast.Expr) bool {
			s, ok := e.(*ast.SelectorExpr)
			if !ok || info.Selections[s] == nil || info.Selections[s].Obj() != onOpenFn {
				return false
			}
			id, ok := s.X.(*ast.Ident)
			return ok && obj["recallExec"] != nil && info.Uses[id] == obj["recallExec"]
		}},
		{"lp", "JRN-s3-2", "openLearning", func(e ast.Expr) bool {
			o := pkg.Scope().Lookup("openLearning")
			return o != nil && callee(info, e) == o
		}},
		{"resumeBoot", "JRN-s3-1", "lp.forgetOwner.wireResume", func(e ast.Expr) bool {
			c, ok := e.(*ast.CallExpr)
			if !ok || callee(info, c) != wireFn {
				return false
			}
			m, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return false
			}
			r, ok := m.X.(*ast.SelectorExpr)
			return ok && info.Selections[r] != nil && info.Selections[r].Obj() == ownerField && isObj(info, r.X, obj["lp"])
		}},
	} {
		o, why := pinned(p.name, p.src, mainFn, parent, info, p.from)
		if why != "" {
			bad = append(bad, fmt.Sprintf("%s: %s", p.req, why))
		}
		obj[p.name] = o
	}
	// Values the checks follow by object may not be copied, so no alias
	// stands in for them: resumeBoot is only called or compared with nil,
	// lp.forgetOwner only selected from (never written, copied or
	// dereferenced), and wireResume only called. Copies of recallDir,
	// verifier, recallExec and lp are harmless: the checks match the calls
	// they vouch for by method or field object, whatever the receiver.
	isNil := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		_, n := info.Uses[id].(*types.Nil)
		return ok && n
	}
	called := func(use, p ast.Node) bool { c, ok := p.(*ast.CallExpr); return ok && c.Fun == use }
	for _, u := range []struct {
		name, req, how string
		obj            types.Object
		ok             func(use, p ast.Node) bool
	}{
		{"resumeBoot", "JRN-s3-2", "only called or compared with nil", obj["resumeBoot"], func(use, p ast.Node) bool {
			switch p := p.(type) {
			case *ast.BinaryExpr:
				return (p.Op == token.EQL || p.Op == token.NEQ) && (p.X == use && isNil(p.Y) || p.Y == use && isNil(p.X))
			case *ast.AssignStmt: // its one write, which pinned checks
				return p.Tok == token.ASSIGN && len(p.Lhs) == 1 && p.Lhs[0] == use
			}
			return called(use, p)
		}},
		{"lp.forgetOwner", "JRN-s3-1", "only selected from, never written or copied", ownerField, func(use, p ast.Node) bool {
			s, ok := p.(*ast.SelectorExpr)
			return ok && s.X == use
		}},
		{"wireResume", "JRN-s3-1", "only called", wireFn, called},
	} {
		if u.obj == nil {
			continue
		}
		if n := usedOnly(mainFn, parent, info, u.obj, u.ok); n != nil {
			bad = append(bad, fmt.Sprintf("%s: %s: %s is used other than %s", u.req, fset.Position(n.Pos()), u.name, u.how))
		}
	}
	dirObj, verObj := obj["recallDir"], obj["verifier"]
	if dirObj == nil || verObj == nil || obj["recallExec"] == nil {
		return bad
	}
	// inPlace follows blocks and if arms only, so main may hold no jump,
	// and no return between the wireResume call and a call it vouches for
	// (main returns early, before it, in held mode and after sign-in).
	var jumps, returns []ast.Node
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.BranchStmt:
			if n.Tok == token.GOTO {
				jumps = append(jumps, n)
			}
		case *ast.LabeledStmt:
			jumps = append(jumps, n)
		case *ast.ReturnStmt:
			returns = append(returns, n)
		}
		return true
	})
	wired := mainFn.Body.Pos()
	placed := func(n ast.Node) string {
		if len(jumps) > 0 {
			return fmt.Sprintf("main() holds a goto or label (at %s), and jumps are not followed", fset.Position(jumps[0].Pos()))
		}
		for _, r := range returns {
			if r.Pos() > wired && r.Pos() < n.Pos() {
				return fmt.Sprintf("main() may return before it, at %s", fset.Position(r.Pos()))
			}
		}
		return inPlace(n, parent, mainFn.Body, info)
	}
	recallCond := func(e ast.Expr) bool {
		b, ok := e.(*ast.BinaryExpr)
		if !ok || b.Op != token.LAND {
			return false
		}
		l, ok1 := b.X.(*ast.BinaryExpr)
		r, ok2 := b.Y.(*ast.BinaryExpr)
		if !ok1 || !ok2 || l.Op != token.NEQ || r.Op != token.NEQ {
			return false
		}
		ld, _ := l.X.(*ast.Ident)
		lit, _ := l.Y.(*ast.BasicLit)
		rv, _ := r.X.(*ast.Ident)
		rn, _ := r.Y.(*ast.Ident)
		if ld == nil || lit == nil || rv == nil || rn == nil {
			return false
		}
		_, isNil := info.Uses[rn].(*types.Nil)
		return info.Uses[ld] == dirObj && lit.Kind == token.STRING && lit.Value == `""` && info.Uses[rv] == verObj && isNil
	}

	// The calls in main.go the order rests on, and the block each
	// statement sits in directly.
	var resumes, attaches, agents []*ast.CallExpr
	var wires []*ast.CallExpr
	assigns := map[ast.Expr]*ast.AssignStmt{}
	block := map[ast.Stmt]*ast.BlockStmt{}
	var arms []*ast.IfStmt
	ast.Inspect(main, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BlockStmt:
			for _, s := range n.List {
				block[s] = n
			}
		case *ast.CallExpr:
			if isObj(info, n.Fun, obj["resumeBoot"]) {
				resumes = append(resumes, n)
			}
			if callee(info, n) == attachFn {
				attaches = append(attaches, n)
			}
			if s, ok := n.Fun.(*ast.SelectorExpr); ok && s.Sel.Name == "Store" {
				if a, ok := s.X.(*ast.SelectorExpr); ok && info.Selections[a] != nil && info.Selections[a].Obj() == agentField {
					agents = append(agents, n)
				}
			}
			if callee(info, n) == wireFn {
				wires = append(wires, n)
			}
		case *ast.AssignStmt:
			if n.Tok == token.ASSIGN && len(n.Lhs) == 1 && len(n.Rhs) == 1 {
				assigns[n.Rhs[0]] = n
			}
		case *ast.IfStmt:
			if n.Init == nil && recallCond(n.Cond) && n.Else != nil {
				arms = append(arms, n)
			}
		}
		return true
	})
	if len(wires) == 1 {
		wired = wires[0].Pos()
	}

	// JRN-s3-1: each arm of the recall if/else runs the boot's resume in
	// place.
	if len(arms) != 1 {
		bad = append(bad, fmt.Sprintf("JRN-s3-1: main.go has %d recall if/else (want 1)", len(arms)))
	}
	for _, a := range arms {
		for _, arm := range []struct {
			name string
			node ast.Node
		}{{"recall-on", a.Body}, {"recall-off", a.Else}} {
			if !callsResumeBoot(arm.node, info, obj["resumeBoot"], placed) {
				bad = append(bad, fmt.Sprintf("JRN-s3-1: %s: the %s arm runs no resumeBoot() in place", fset.Position(arm.node.Pos()), arm.name))
			}
		}
	}

	// JRN-s3-2: lp.attach( and forgetOwner.agent.Store( each run in place
	// in main() (not in a go or defer statement, a closure or a dead
	// branch), and every resumeBoot() comes after all of them in source
	// order.
	if len(attaches) == 0 || len(agents) == 0 {
		bad = append(bad, fmt.Sprintf("JRN-s3-2: main.go calls lp.attach %d times and forgetOwner.agent.Store %d times (want some of each)", len(attaches), len(agents)))
	}
	for _, c := range append(append([]*ast.CallExpr(nil), attaches...), agents...) {
		if why := placed(c); why != "" {
			bad = append(bad, fmt.Sprintf("JRN-s3-2: %s: %s does not run in place: %s", fset.Position(c.Pos()), types.ExprString(c.Fun), why))
		}
		for _, r := range resumes {
			if r.Pos() < c.Pos() {
				bad = append(bad, fmt.Sprintf("JRN-s3-2: %s: resumeBoot() runs before %s", fset.Position(r.Pos()), fset.Position(c.Pos())))
			}
		}
	}

	// JRN-s3-3: wireResume's second argument is onOpen, pinned to one
	// write from recallExec.OnOpen, made as a statement directly in the
	// recall guard's body, which sits in the same block as the wireResume
	// call, in place, and before it; nothing else in main.go reaches
	// recall's OnOpen. Checked by go/types object, so aliases,
	// parentheses and method expressions count.
	if len(wires) != 1 {
		bad = append(bad, fmt.Sprintf("JRN-s3-3: main.go calls wireResume %d times (want 1)", len(wires)))
	}
	for _, w := range wires {
		if p := onOpenWiring(info, main, inMain, w, onOpenFn, obj["recallExec"], assigns, block, recallCond, placed); p != "" {
			bad = append(bad, fmt.Sprintf("JRN-s3-3: %s: %s", fset.Position(w.Pos()), p))
		}
	}
	return bad
}

// onOpenWiring says how the wireResume call w is not handed recall's
// OnOpen as JRN-s3-3 requires, or "" when it is.
func onOpenWiring(info *types.Info, main *ast.File, inMain func(ast.Node) bool, w *ast.CallExpr, onOpenFn, recallExec types.Object, assigns map[ast.Expr]*ast.AssignStmt, block map[ast.Stmt]*ast.BlockStmt, recallCond func(ast.Expr) bool, placed func(ast.Node) string) string {
	var uses []*ast.SelectorExpr
	for sel, s := range info.Selections {
		if s.Obj() == onOpenFn && inMain(sel) {
			uses = append(uses, sel)
		}
	}
	if len(uses) != 1 {
		return fmt.Sprintf("main.go reaches recall's OnOpen %d times (want 1)", len(uses))
	}
	use := uses[0]
	if !isObj(info, use.X, recallExec) {
		return "recall's OnOpen is not taken from recallExec"
	}
	set := assigns[use]
	if set == nil {
		return "recallExec.OnOpen is not the whole right side of an assignment"
	}
	guard := (*ast.IfStmt)(nil)
	if b := block[set]; b != nil {
		ast.Inspect(main, func(n ast.Node) bool {
			if g, ok := n.(*ast.IfStmt); ok && g.Body == b {
				guard = g
			}
			return guard == nil
		})
	}
	if guard == nil || guard.Init != nil || !recallCond(guard.Cond) {
		return "recallExec.OnOpen is not set directly in the body of `if recallDir != \"\" && verifier != nil`"
	}
	if len(w.Args) != 2 {
		return "wireResume does not take two arguments"
	}
	arg, _ := w.Args[1].(*ast.Ident)
	v, _ := info.Uses[arg].(*types.Var)
	lhs, _ := set.Lhs[0].(*ast.Ident)
	if arg == nil || v == nil || lhs == nil || info.Uses[lhs] != v {
		return "wireResume's second argument is not the variable set from recallExec.OnOpen"
	}
	n := 0
	for _, obj := range info.Uses {
		if obj == v {
			n++
		}
	}
	if n != 2 {
		return fmt.Sprintf("the variable set from recallExec.OnOpen is used %d times (want 2: set, then passed)", n)
	}
	var call ast.Stmt
	for s := range block {
		if a, ok := s.(*ast.AssignStmt); ok && len(a.Rhs) == 1 && a.Rhs[0] == ast.Expr(w) {
			call = s
		}
	}
	if call == nil || block[call] != block[guard] || guard.Pos() > call.Pos() {
		return "the recall guard is not in the wireResume call's block, before it"
	}
	if why := placed(call); why != "" {
		return "the wireResume call does not run in place: " + why
	}
	return ""
}

// agentosdTyping is what type-checking agentosd needs: its import path,
// the files this build compiles and an importer over the export data go
// list builds for its imports.
type agentosdTyping struct {
	path    string
	goFiles map[string]bool
	imp     types.Importer
}

var agentosdTyped *agentosdTyping

func agentosdTypes(t *testing.T) *agentosdTyping {
	t.Helper()
	if agentosdTyped != nil {
		return agentosdTyped
	}
	cmd := exec.Command("go", "list", "-export", "-deps", "-json=ImportPath,Export,GoFiles,DepOnly,Error", ".")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	tc := &agentosdTyping{goFiles: map[string]bool{}}
	export := map[string]string{}
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p struct {
			ImportPath, Export string
			GoFiles            []string
			DepOnly            bool
			Error              *struct{ Err string }
		}
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if p.Error != nil {
			t.Fatalf("go list %s: %s", p.ImportPath, p.Error.Err)
		}
		export[p.ImportPath] = p.Export
		if !p.DepOnly {
			tc.path = p.ImportPath
			for _, f := range p.GoFiles {
				tc.goFiles[f] = true
			}
		}
	}
	if tc.path == "" {
		t.Fatal("go list did not list agentosd")
	}
	tc.imp = importer.ForCompiler(token.NewFileSet(), "gc", func(path string) (io.ReadCloser, error) {
		e, ok := export[path]
		if !ok || e == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(e)
	})
	agentosdTyped = tc
	return tc
}

// isObj reports whether e, unparenthesised, is an identifier for obj.
func isObj(info *types.Info, e ast.Expr, obj types.Object) bool {
	id, ok := ast.Unparen(e).(*ast.Ident)
	return ok && obj != nil && info.Uses[id] == obj
}

// usedOnly returns the first use of obj in fn, an identifier for it or a
// selector selecting it, that ok refuses given its parent, or nil.
func usedOnly(fn *ast.FuncDecl, parent map[ast.Node]ast.Node, info *types.Info, obj types.Object, ok func(use, p ast.Node) bool) ast.Node {
	var bad ast.Node
	ast.Inspect(fn, func(n ast.Node) bool {
		if bad != nil {
			return false
		}
		switch n := n.(type) {
		case *ast.Ident:
			if s, sel := parent[n].(*ast.SelectorExpr); sel && s.Sel == n {
				return true // the selector itself is the use
			}
			if info.Uses[n] == obj && !ok(n, parent[n]) {
				bad = n
			}
		case *ast.SelectorExpr:
			if s := info.Selections[n]; s != nil && s.Obj() == obj && !ok(n, parent[n]) {
				bad = n
			}
		}
		return true
	})
	return bad
}

// callee returns the object the call e calls, or nil.
func callee(info *types.Info, e ast.Expr) types.Object {
	c, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return nil
	}
	switch f := ast.Unparen(c.Fun).(type) {
	case *ast.Ident:
		return info.Uses[f]
	case *ast.SelectorExpr:
		return info.Uses[f.Sel]
	}
	return nil
}

// pinned finds main's variable name and says why it is not pinned, or ""
// when it is: fn declares it once (so nothing shadows it) and writes it
// once, from what from accepts. A write is an assignment or a declared
// value; taking its address counts as one, the call it is passed to (so
// flag.StringVar(&x, ...) is x's write), and is a write from nothing
// anywhere else, as are ++, --, op= and range.
func pinned(name, src string, fn *ast.FuncDecl, parent map[ast.Node]ast.Node, info *types.Info, from func(ast.Expr) bool) (types.Object, string) {
	var obj types.Object
	defs := 0
	for id, o := range info.Defs {
		if id.Name != name || o == nil || id.Pos() < fn.Pos() || id.Pos() >= fn.End() {
			continue
		}
		defs++
		if obj == nil || o.Pos() < obj.Pos() {
			obj = o
		}
	}
	if obj == nil {
		return nil, fmt.Sprintf("main() declares no %s", name)
	}
	is := func(e ast.Expr) bool {
		id, ok := ast.Unparen(e).(*ast.Ident)
		return ok && (info.Uses[id] == obj || info.Defs[id] == obj)
	}
	var writes []ast.Expr
	ast.Inspect(fn, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, l := range n.Lhs {
				if !is(l) {
					continue
				}
				switch {
				case n.Tok != token.ASSIGN && n.Tok != token.DEFINE:
					writes = append(writes, nil)
				case len(n.Rhs) == len(n.Lhs):
					writes = append(writes, n.Rhs[i])
				default:
					writes = append(writes, n.Rhs[0])
				}
			}
		case *ast.ValueSpec:
			for i, id := range n.Names {
				if !is(id) || len(n.Values) == 0 {
					continue
				}
				if len(n.Values) == len(n.Names) {
					writes = append(writes, n.Values[i])
				} else {
					writes = append(writes, n.Values[0])
				}
			}
		case *ast.UnaryExpr:
			if n.Op == token.AND && is(n.X) {
				if c, ok := parent[n].(*ast.CallExpr); ok {
					writes = append(writes, c)
				} else {
					writes = append(writes, nil)
				}
			}
		case *ast.IncDecStmt:
			if is(n.X) {
				writes = append(writes, nil)
			}
		case *ast.RangeStmt:
			if (n.Key != nil && is(n.Key)) || (n.Value != nil && is(n.Value)) {
				writes = append(writes, nil)
			}
		}
		return true
	})
	if defs != 1 {
		return obj, fmt.Sprintf("main() declares %s %d times (want 1: nothing shadows it)", name, defs)
	}
	if len(writes) != 1 || writes[0] == nil {
		return obj, fmt.Sprintf("%s is written %d time(s) (want once, from %s)", name, len(writes), src)
	}
	if !from(writes[0]) {
		return obj, fmt.Sprintf("%s is written once, but not from %s", name, src)
	}
	return obj, ""
}

// callsResumeBoot reports whether n holds a call of main's resumeBoot,
// the object boot, that placed finds in place.
func callsResumeBoot(n ast.Node, info *types.Info, boot types.Object, placed func(ast.Node) string) bool {
	found := false
	ast.Inspect(n, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if isObj(info, c.Fun, boot) && placed(c) == "" {
				found = true
			}
		}
		return !found
	})
	return found
}

// inPlace says why n, a call or a statement, does not run in place as
// main's own code, or "" when it does: a call must be a statement of its
// own, and the statement reached from body only through blocks and the
// arms of ifs with no constant in their condition. So a go or defer
// statement, a closure, a loop, a switch or a dead branch on the way
// fails it, whatever it is spelled as.
func inPlace(n ast.Node, parent map[ast.Node]ast.Node, body *ast.BlockStmt, info *types.Info) string {
	if _, ok := n.(*ast.CallExpr); ok {
		s, ok := parent[n].(*ast.ExprStmt)
		if !ok {
			return fmt.Sprintf("not a statement of its own (in a %T)", parent[n])
		}
		n = s
	}
	for n != body {
		switch p := parent[n].(type) {
		case *ast.BlockStmt:
		case *ast.IfStmt:
			if n != p.Body && n != p.Else {
				return "in an if's init or condition"
			}
			if c := boolConst(p.Cond, info); c != nil {
				return fmt.Sprintf("under an if whose condition holds the constant %s", types.ExprString(c))
			}
		case nil:
			return "not in main()"
		default:
			return fmt.Sprintf("inside a %T", p)
		}
		n = parent[n]
	}
	return ""
}

// boolConst returns the first boolean constant in e, or nil.
func boolConst(e ast.Expr, info *types.Info) ast.Expr {
	var c ast.Expr
	ast.Inspect(e, func(n ast.Node) bool {
		if x, ok := n.(ast.Expr); ok && c == nil {
			if tv, ok := info.Types[x]; ok && tv.Value != nil {
				if b, ok := tv.Type.Underlying().(*types.Basic); ok && b.Info()&types.IsBoolean != 0 {
					c = x
				}
			}
		}
		return c == nil
	})
	return c
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
