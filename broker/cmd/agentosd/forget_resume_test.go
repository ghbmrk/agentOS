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
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/recalltool"
)

// fakeRecallOpen stands in for recall's LateExecutor in bootRecall:
// OnOpen's callbacks wait for open, and one registered after it runs at
// once.
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

func (o *fakeRecallOpen) Off() {}

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
		rec := &fakeRecallOpen{}
		boot := newBootRecall(ctx, &learning{forgetOwner: r.f}, c.recall, rec, func(bool) {})
		boot.open = func(context.Context, *modelroute.Verifier, recalltool.ServiceConfig, *recalltool.Late, *recalltool.LateExecutor) {
			rec.Open()
		}
		setup := func() {
			r.f.gate.Store(gate)
			if !c.noAgent {
				r.withAgent(w)
			}
			boot.finish(recalltool.ServiceConfig{}, nil)
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

// fakeSwitch stands in for recall's LateExecutor in bootRecall: it notes
// each call and runs nothing.
type fakeSwitch struct{ note func(string) }

func (s *fakeSwitch) OnOpen(func()) { s.note("OnOpen") }
func (s *fakeSwitch) Off()          { s.note("Off") }

// JRN-startup-reconcile s3 (Security R1 and Potency PT1 on #1382, #2507,
// S1 S2 on #2513): bootRecall, driven with fakes, runs the boot's resume on
// both arms of boot setup's end (JRN-s3-1): recall on, before recall opens
// with finish's ServiceConfig and Late, so the boot's resume waits for the
// open; recall off, after the executor is marked off and STATUS told
// recall is not wired, so the owner is told recall is off. Wiring runs
// none of them, and with recall on wireResume is handed recall's OnOpen.
//
// Brief JRN-startup-reconcile-s3: JRN-s3-1 (subtest names).
// REQ: CAP-3, OP-4
func TestBootRecallFinishOrder(t *testing.T) {
	on := []string{"boot", "OnOpen", "open"}
	off := []string{"Off", "wired false", "boot"}
	for _, c := range []struct {
		name     string
		learning bool
		on       bool
		want     []string
	}{
		{"recall on", true, true, on},
		{"recall off", true, false, off},
		{"recall on with no learning", false, true, []string{"open"}},
		{"recall off with no learning", false, false, []string{"Off", "wired false"}},
	} {
		t.Run("JRN-s3-1 "+c.name, func(t *testing.T) {
			var mu sync.Mutex
			var got []string
			note := func(s string) {
				mu.Lock()
				got = append(got, s)
				mu.Unlock()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var lp *learning
			var f *ownerForget
			if c.learning {
				f = newForgetRig(t).f
				lp = &learning{forgetOwner: f}
				t.Cleanup(func() { waitIdle(f) }) // after cancel, before the rig's dirs go
			}
			b := newBootRecall(ctx, lp, c.on, &fakeSwitch{note: note}, func(on bool) { note(fmt.Sprintf("wired %v", on)) })
			if b.on != c.on || b.ctx != ctx {
				t.Fatalf("recall on = %v, ctx kept %v; want %v and true", b.on, b.ctx == ctx, c.on)
			}
			if f != nil && (f.noRecall == c.on || (f.whenOpen != nil) != c.on) {
				t.Fatalf("wired noRecall %v, whenOpen set %v; want recall on = %v", f.noRecall, f.whenOpen != nil, c.on)
			}
			if (b.boot != nil) != c.learning {
				t.Fatalf("boot's resume set = %v, want %v", b.boot != nil, c.learning)
			}
			if boot := b.boot; boot != nil {
				b.boot = func() { note("boot"); boot() }
			}
			v, exec := modelroute.NewVerifier(t.TempDir()+"/verify.sock"), &recalltool.LateExecutor{}
			sc, late := recalltool.ServiceConfig{Dir: "recall"}, &recalltool.Late{}
			b.v, b.exec = v, exec
			opened := make(chan struct{})
			b.open = func(octx context.Context, ov *modelroute.Verifier, osc recalltool.ServiceConfig, olate *recalltool.Late, oexec *recalltool.LateExecutor) {
				if octx != ctx || ov != v || osc.Dir != sc.Dir || olate != late || oexec != exec {
					t.Errorf("recall opened with ctx %v, verifier %v, dir %q, Late %v, executor %v; want finish's and the wire's",
						octx == ctx, ov == v, osc.Dir, olate == late, oexec == exec)
				}
				note("open")
				close(opened)
			}
			mu.Lock()
			wired := len(got)
			mu.Unlock()
			if wired != 0 {
				t.Fatalf("wiring ran %q", got)
			}
			b.finish(sc, late)
			if c.on {
				select {
				case <-opened:
				case <-time.After(5 * time.Second):
					t.Fatal("recall never opened")
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if strings.Join(got, " ") != strings.Join(c.want, " ") {
				t.Errorf("finish ran %q, want %q", got, c.want)
			}
		})
	}
}

// wireBootRecall hands bootRecall recall's own pieces (S1 S2 on #2513):
// recall is on exactly when it has a directory and a verifier
// (JRN-s3-3); it opens through openRecall on that verifier and the
// executor given, which is also the switch finish marks off; and with
// recall off, finish's wired(false) puts recall's off line in STATUS.
//
// Brief JRN-startup-reconcile-s3: JRN-s3-3 (subtest names).
// REQ: CAP-3, OP-4
func TestWireBootRecallHandsRecallsOwn(t *testing.T) {
	v := modelroute.NewVerifier(t.TempDir() + "/verify.sock") // never dialled
	for _, c := range []struct {
		name, dir string
		v         *modelroute.Verifier
		on        bool
	}{
		{"recall on", "recall", v, true},
		{"recall off with no directory", "", v, false},
		{"recall off with no verifier", "recall", nil, false},
		{"recall off with neither", "", nil, false},
	} {
		t.Run("JRN-s3-3 "+c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			exec, caps := &recalltool.LateExecutor{}, newCapState("")
			f := newForgetRig(t).f
			t.Cleanup(func() { waitIdle(f) })
			b := wireBootRecall(ctx, &learning{forgetOwner: f}, c.dir, c.v, exec, caps)
			if b.on != c.on || f.noRecall == c.on || (f.whenOpen != nil) != c.on {
				t.Errorf("recall on = %v, wired noRecall %v, whenOpen set %v; want recall on = %v", b.on, f.noRecall, f.whenOpen != nil, c.on)
			}
			if b.ex != recallSwitch(exec) || b.exec != exec || b.v != c.v || b.ctx != ctx || b.boot == nil {
				t.Errorf("switch %v, executor %v, verifier %v, ctx %v, boot's resume %v kept; want all", b.ex == recallSwitch(exec), b.exec == exec, b.v == c.v, b.ctx == ctx, b.boot != nil)
			}
			if b.open == nil || reflect.ValueOf(b.open).Pointer() != reflect.ValueOf(openRecall).Pointer() {
				t.Error("recall does not open through openRecall")
			}
			if caps.recallLine() != "" {
				t.Fatalf("STATUS says %q before boot setup's end", caps.recallLine())
			}
			b.wired(false)
			if caps.recallLine() != recallOffLine {
				t.Errorf("wired(false): STATUS says %q, want %q", caps.recallLine(), recallOffLine)
			}
		})
	}
}

// main wires FORGET's boot resume through bootRecall alone: one
// wireBootRecall call, given main's own lp, recallDir, verifier and
// recallExec, before daemon.Run, and one finish of what it returns after
// lp.attach and lp.forgetOwner.agent.Store (PT1 and S3 on #1382: dropping
// the wiring passed every other test). Each mutant must break only its
// listed requirements, and the real source must pass. TestBootRecallFinishOrder
// checks what bootRecall does; this checks only where main calls it.
//   - JRN-s3-1: finish dropped, run twice, in a goroutine, a dead branch,
//     a branch on runsc, or through a copy; wireBootRecall called twice
//     (Q1..Q5, S14, W2).
//   - JRN-s3-2: finish before daemon.Run or before lp.attach, or the wire
//     after daemon.Run (R1, R1b, W1); lp.attach or the agent Store not run
//     in place, on another receiver, or through a copy (R2..R7, X1..X4);
//     lp reassigned or lp.forgetOwner replaced (P4, M); the resume reached
//     by another path: resumeAgent or whenOpen called from main, or
//     resumeAgent through an interface from a function of its own (S3,
//     S3b, N1).
//   - JRN-s3-3: recall's inputs not main's own: a constant, a fresh
//     executor or capState, recallDir or verifier rewritten, finish given
//     another ServiceConfig or Late, or wireResume called outside
//     wireBootRecall (A1..A8, P3, W3); recall opened, switched off or told
//     STATUS by another path: openRecall, recallWired, recallOff, or the
//     executor's Off, OnOpen, Set or Failed reached from main, directly,
//     through an interface or from a look-alike finish (S1, S2, S2b,
//     S13..S13c, N2..N5).
//     R1 (an early finish) also breaks JRN-s3-3: its config is not main's.
//
// The reach check: openRecall, recallWired and newBootRecall are reached
// only from wireBootRecall; wireResume only from newBootRecall; the
// executor's Off and OnOpen only from newBootRecall and finish, its Set
// and Failed only from openRecall; recallOff only from capState's
// methods; resumeAgent and the resume and whenOpen fields only from
// ownerForget's methods; and bootRecall's fields are set only by
// newBootRecall and wireBootRecall. Callers and setters go by type-checked
// object, not name, and a method called through an interface counts as
// the entry with its name and signature.
//   - F1, F2: a goto, or a return between the wire and a call it vouches
//     for. main may hold neither.
//
// Out of reach without data-flow analysis: a condition false only at run
// time, and leaving main (log.Fatal, os.Exit, panic) or blocking before
// finish. Reflection (reflect.ValueOf(recallExec).MethodByName("Off"))
// reaches a method with no identifier to check; agentosd imports no
// reflect outside its tests.
// Later: flag.Set("recall", ...) writes recallDir with no assignment or
// address.
//
// Brief JRN-startup-reconcile-s3: JRN-s3-1..4 (subtest names).
// REQ: CAP-3, OP-4
func TestForgetResumeIsWiredOnlyThroughWireResume(t *testing.T) {
	srcs := agentosdSources(t)
	t.Run("JRN-s3-4 production wiring passes", func(t *testing.T) {
		for _, bad := range forgetBootWiring(t, srcs) {
			t.Error(bad)
		}
	})
	wire := "\tforgetBoot := wireBootRecall(ctx, lp, recallDir, verifier, recallExec, caps)\n"
	run := "\td, err := daemon.Run(ctx, cfg)\n"
	finish := "\tforgetBoot.finish(recallCfg, recallTools)\n"
	attach := "\t\tlp.attach(ctx, d)\n"
	store := "\t\t\t\tlp.forgetOwner.agent.Store(&forgetAgent{work: recallExec,\n\t\t\t\t\tlineage: func() (string, error) { return machines{m}.Lineage(agentMachine) }})\n"
	attachIf := "\tif lp != nil {\n" + attach
	fn := "func main() {\n"
	for _, m := range []struct {
		name, req string
		edits     []string // old, new pairs
	}{
		// recallCfg is set after daemon.Run, so the early finish cannot be given it.
		{"R1 finish before daemon.Run", "JRN-s3-2 JRN-s3-3", []string{finish, "", run, "\tforgetBoot.finish(recalltool.ServiceConfig{}, recallTools)\n" + run}},
		{"R1b finish before lp.attach", "JRN-s3-2", []string{finish, "", attachIf, finish + attachIf}},
		{"W1 wired after daemon.Run", "JRN-s3-2", []string{wire + run, run + wire}},
		{"R2 lp.attach in its own goroutine", "JRN-s3-2", []string{attach, "\t\tgo lp.attach(ctx, d)\n"}},
		{"R3 lp.attach in a goroutine's closure", "JRN-s3-2", []string{attach, "\t\tgo func() { lp.attach(ctx, d) }()\n"}},
		{"R4 lp.attach in a deferred closure", "JRN-s3-2", []string{attach, "\t\tdefer func() { lp.attach(ctx, d) }()\n"}},
		{"R5 lp.attach in an uncalled closure", "JRN-s3-2", []string{attach, "\t\t_ = func() { lp.attach(ctx, d) }\n"}},
		{"R6 lp.attach in a dead branch", "JRN-s3-2", []string{attach, "\t\tif false {\n\t" + attach + "\t\t}\n"}},
		{"R7 agent Store in a goroutine's closure", "JRN-s3-2", []string{store, "\t\t\t\tgo func() {\n" + store + "\t\t\t\t}()\n"}},
		{"X1 attach on another learning", "JRN-s3-2", []string{attach, "\t\tnew(learning).attach(ctx, d)\n"}},
		{"X2 agent Store on another owner", "JRN-s3-2", []string{"lp.forgetOwner.agent.Store(", "new(ownerForget).agent.Store("}},
		{"X3 agent Store through a copy of lp.forgetOwner", "JRN-s3-2", []string{"\t\t\t\tlp.forgetOwner.agent.Store(", "\t\t\t\tfo := lp.forgetOwner\n\t\t\t\tfo.agent.Store("}},
		{"X4 attach through a copy of lp", "JRN-s3-2", []string{attach, "\t\tl := lp\n\t\tl.attach(ctx, d)\n"}},
		{"P4 lp reassigned", "JRN-s3-2", []string{attach, "\t\tlp = nil\n" + attach}},
		{"M lp.forgetOwner replaced", "JRN-s3-2", []string{wire, "\tif lp != nil {\n\t\tlp.forgetOwner = new(ownerForget)\n\t}\n" + wire}},
		{"Q1 finish dropped", "JRN-s3-1", []string{finish, ""}},
		{"Q2 finish in a goroutine", "JRN-s3-1", []string{finish, "\tgo " + finish[1:]}},
		{"Q3 finish in a dead branch", "JRN-s3-1", []string{finish, "\tif false {\n" + finish + "\t}\n"}},
		{"Q4 finish through a copy", "JRN-s3-1", []string{finish, "\tfb := forgetBoot\n\tfb." + finish[len("\tforgetBoot."):]}},
		{"Q5 finish twice", "JRN-s3-1", []string{finish, finish + finish}},
		{"W2 wired twice", "JRN-s3-1", []string{wire, "\t_ = wireBootRecall(ctx, lp, recallDir, verifier, recallExec, caps)\n" + wire}},
		{"S14 finish in a branch", "JRN-s3-1", []string{finish, "\tif runsc != \"\" {\n\t" + finish + "\t}\n"}},
		{"W3 wireResume called in main", "JRN-s3-3", []string{wire, wire + "\tif lp != nil {\n\t\t_ = lp.forgetOwner.wireResume(ctx, nil)\n\t}\n"}},
		{"A1 recall's directory a constant", "JRN-s3-3", []string{wire, "\tforgetBoot := wireBootRecall(ctx, lp, \"\", verifier, recallExec, caps)\n"}},
		{"A2 recall's verifier nil", "JRN-s3-3", []string{wire, "\tforgetBoot := wireBootRecall(ctx, lp, recallDir, nil, recallExec, caps)\n"}},
		{"A3 a fresh executor", "JRN-s3-3", []string{wire, "\tforgetBoot := wireBootRecall(ctx, lp, recallDir, verifier, &recalltool.LateExecutor{}, caps)\n"}},
		{"A4 recallDir set before the wire", "JRN-s3-3", []string{wire, "\trecallDir = \"on\"\n" + wire}},
		{"P3 verifier reassigned", "JRN-s3-3", []string{wire, "\tverifier = nil\n" + wire}},
		{"A5 recall's STATUS on fresh caps", "JRN-s3-3", []string{wire, "\tforgetBoot := wireBootRecall(ctx, lp, recallDir, verifier, recallExec, newCapState(\"\"))\n"}},
		{"A6 finish given an empty ServiceConfig", "JRN-s3-3", []string{finish, "\tforgetBoot.finish(recalltool.ServiceConfig{}, recallTools)\n"}},
		{"A7 finish given a fresh Late", "JRN-s3-3", []string{finish, "\tforgetBoot.finish(recallCfg, &recalltool.Late{})\n"}},
		{"A8 recallCfg reassigned", "JRN-s3-3", []string{finish, "\trecallCfg = recalltool.ServiceConfig{}\n" + finish}},
		{"S1 openRecall called in main", "JRN-s3-3", []string{finish, "\tgo openRecall(ctx, verifier, recallCfg, recallTools, recallExec)\n" + finish}},
		{"S2 recall's STATUS switched in main", "JRN-s3-3", []string{finish, "\tcaps.recallWired(false)\n" + finish}},
		{"S2b recall's STATUS field set in main", "JRN-s3-3", []string{finish, "\tcaps.recallOff.Store(true)\n" + finish}},
		{"S13 executor marked off in main", "JRN-s3-3", []string{run, "\trecallExec.Off()\n" + run}},
		{"S13b executor marked off through recallSwitch", "JRN-s3-3", []string{run, "\trecallSwitch(recallExec).Off()\n" + run}},
		{"S13c OnOpen registered in main", "JRN-s3-3", []string{run, "\trecallExec.OnOpen(func() {})\n" + run}},
		{"S3 resumeAgent started in main", "JRN-s3-2", []string{run, "\tif lp != nil {\n\t\tgo lp.forgetOwner.resumeAgent(ctx)\n\t}\n" + run}},
		{"S3b whenOpen run in main", "JRN-s3-2", []string{run, "\tif lp != nil && lp.forgetOwner.whenOpen != nil {\n\t\tlp.forgetOwner.whenOpen()\n\t}\n" + run}},
		{"N1 resumeAgent through an interface, from a look-alike", "JRN-s3-2", []string{fn, "func kick(ctx context.Context, l *learning) {\n\tvar i interface{ resumeAgent(context.Context) } = l.forgetOwner\n\tgo i.resumeAgent(ctx)\n}\n\n" + fn, run, "\tif lp != nil {\n\t\tkick(ctx, lp)\n\t}\n" + run}},
		{"N2 recall's STATUS switched through an interface", "JRN-s3-3", []string{finish, "\tvar cw interface{ recallWired(bool) } = caps\n\tcw.recallWired(false)\n" + finish}},
		{"N3 executor set in main", "JRN-s3-3", []string{run, "\trecallExec.Set(&recalltool.Reach{})\n" + run}},
		{"N4 executor marked off by a look-alike finish", "JRN-s3-3", []string{fn, "type early struct{}\n\nfunc (early) finish(x *recalltool.LateExecutor) { x.Off() }\n\n" + fn, run, "\tearly{}.finish(recallExec)\n" + run}},
		{"N5 executor marked failed in main", "JRN-s3-3", []string{run, "\trecallExec.Failed()\n" + run}},
		{"F1 goto past lp.attach", "JRN-s3-1 JRN-s3-2", []string{attach, "\t\tgoto attached\n" + attach + "\tattached:\n"}},
		{"F2 return before lp.attach", "JRN-s3-1 JRN-s3-2", []string{attach, "\t\tif ctx.Err() != nil {\n\t\t\treturn\n\t\t}\n" + attach}},
	} {
		t.Run(m.req+" "+m.name+" fails", func(t *testing.T) {
			src := srcs["main.go"]
			for i := 0; i < len(m.edits); i += 2 {
				if n := strings.Count(src, m.edits[i]); n != 1 {
					t.Fatalf("main.go holds the mutated text %d times (want 1): %q", n, m.edits[i])
				}
				src = strings.Replace(src, m.edits[i], m.edits[i+1], 1)
			}
			mut := make(map[string]string, len(srcs))
			for k, v := range srcs {
				mut[k] = v
			}
			mut["main.go"] = src
			// The mutant breaks each of its own requirements and
			// nothing else.
			reqs := strings.Fields(m.req)
			broke := map[string]bool{}
			for _, b := range forgetBootWiring(t, mut) {
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

// forgetBootWiring parses agentosd's sources, type-checks the ones this
// build compiles, and lists each way main calls bootRecall wrong, each
// prefixed with the requirement it breaks.
func forgetBootWiring(t *testing.T, srcs map[string]string) []string {
	t.Helper()
	tc := agentosdTypes(t)
	var bad []string
	fset := token.NewFileSet()
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
	// Soft errors (a variable declared and not used, as in Q1) still
	// leave info whole; anything else is a mutant that does not parse as Go.
	conf := types.Config{Importer: tc.imp, Error: func(err error) {
		if te, ok := err.(types.Error); !ok || !te.Soft {
			t.Fatalf("type-check: %v", err)
		}
	}}
	pkg, _ := conf.Check(tc.path, fset, files, info)
	method := func(o types.Object, name string) types.Object {
		if o == nil {
			return nil
		}
		m, _, _ := types.LookupFieldOrMethod(types.NewPointer(o.Type()), false, o.Pkg(), name)
		return m
	}
	member := func(typ, name string) types.Object { return method(pkg.Scope().Lookup(typ), name) }
	var lateExec types.Object
	for _, p := range pkg.Imports() {
		if strings.HasSuffix(p.Path(), "/recalltool") {
			lateExec = p.Scope().Lookup("LateExecutor")
		}
	}
	wireBoot, newBoot, openFn := pkg.Scope().Lookup("wireBootRecall"), pkg.Scope().Lookup("newBootRecall"), pkg.Scope().Lookup("openRecall")
	finishFn, wireFn := member("bootRecall", "finish"), member("ownerForget", "wireResume")
	ownerField, attachFn, agentField := member("learning", "forgetOwner"), member("learning", "attach"), member("ownerForget", "agent")
	// Each field the wiring sets, and the one function that may set it.
	setter := map[types.Object]types.Object{}
	for _, f := range []struct {
		typ, field string
		fn         types.Object
	}{
		{"ownerForget", "resume", wireFn}, {"ownerForget", "whenOpen", wireFn}, {"ownerForget", "noRecall", wireFn},
		{"bootRecall", "on", newBoot}, {"bootRecall", "ex", newBoot}, {"bootRecall", "boot", newBoot},
		{"bootRecall", "ctx", newBoot}, {"bootRecall", "wired", newBoot},
		{"bootRecall", "open", wireBoot}, {"bootRecall", "v", wireBoot}, {"bootRecall", "exec", wireBoot},
	} {
		if o := member(f.typ, f.field); o != nil {
			setter[o] = f.fn
		}
	}
	bootType := pkg.Scope().Lookup("bootRecall")
	// What starts or opens recall, marks it off, failed or open, says so in
	// STATUS, or runs the FORGET resume, and the functions or the receiver
	// type that alone may reach it (S1 S2 S3 S13 N1..N4 on #2513). Callers
	// go by object, not name, so a look-alike function or method of another
	// type is not one of them.
	type rule struct {
		req, from string
		fns       []types.Object // the functions that may reach it
		owner     types.Object   // or the type whose methods may
	}
	capType, ownerType := pkg.Scope().Lookup("capState"), pkg.Scope().Lookup("ownerForget")
	fromWire := rule{req: "JRN-s3-3", from: "wireBootRecall", fns: []types.Object{wireBoot}}
	reach := map[types.Object]rule{}
	for _, r := range []struct {
		o types.Object
		rule
	}{
		{openFn, fromWire},
		{member("capState", "recallWired"), fromWire},
		{newBoot, fromWire},
		{member("capState", "recallOff"), rule{req: "JRN-s3-3", from: "capState's methods", owner: capType}},
		{member("ownerForget", "resumeAgent"), rule{req: "JRN-s3-2", from: "ownerForget's methods", owner: ownerType}},
		{member("ownerForget", "resume"), rule{req: "JRN-s3-2", from: "ownerForget's methods", owner: ownerType}},
		{member("ownerForget", "whenOpen"), rule{req: "JRN-s3-2", from: "ownerForget's methods", owner: ownerType}},
		{wireFn, rule{req: "JRN-s3-3", from: "newBootRecall", fns: []types.Object{newBoot}}},
		{method(lateExec, "Off"), rule{req: "JRN-s3-3", from: "newBootRecall and bootRecall.finish", fns: []types.Object{newBoot, finishFn}}},
		{method(lateExec, "OnOpen"), rule{req: "JRN-s3-3", from: "newBootRecall and bootRecall.finish", fns: []types.Object{newBoot, finishFn}}},
		{method(lateExec, "Set"), rule{req: "JRN-s3-3", from: "openRecall", fns: []types.Object{openFn}}},
		{method(lateExec, "Failed"), rule{req: "JRN-s3-3", from: "openRecall", fns: []types.Object{openFn}}},
	} {
		if r.o != nil {
			reach[r.o] = r.rule
		}
	}
	if wireBoot == nil || newBoot == nil || openFn == nil || finishFn == nil || wireFn == nil || ownerField == nil || attachFn == nil || agentField == nil ||
		bootType == nil || capType == nil || ownerType == nil || len(setter) != 11 || len(reach) != 12 {
		return append(bad, "wiring: no wireBootRecall, newBootRecall, openRecall, bootRecall.finish or its fields, ownerForget.wireResume, .agent or its resume fields, learning.forgetOwner or .attach, or what recall opens and switches through")
	}
	// A method called through an interface is the entry's own when it
	// has the entry's name and signature: an interface of main's own may
	// carry recallWired, resumeAgent, Off or OnOpen (N1, N2, S13b).
	lookup := func(o types.Object) (rule, bool) {
		if r, ok := reach[o]; ok {
			return r, true
		}
		f, ok := o.(*types.Func)
		if !ok {
			return rule{}, false
		}
		if sig := f.Type().(*types.Signature); sig.Recv() == nil || !types.IsInterface(sig.Recv().Type()) {
			return rule{}, false
		}
		for c, r := range reach {
			if _, ok := c.(*types.Func); ok && c.Name() == f.Name() && types.Identical(c.Type(), f.Type()) {
				return r, true
			}
		}
		return rule{}, false
	}

	// Package-wide: those fields are set only by their setter, bootRecall
	// built only by newBootRecall, each reach entry reached only from its
	// own, and wireBootRecall reached once.
	wireBoots := 0
	for _, f := range files {
		for _, d := range f.Decls {
			var caller, recv types.Object
			if fn, ok := d.(*ast.FuncDecl); ok && info.Defs[fn.Name] != nil {
				caller = info.Defs[fn.Name]
				if r := caller.Type().(*types.Signature).Recv(); r != nil {
					rt := r.Type()
					if p, ok := rt.(*types.Pointer); ok {
						rt = p.Elem()
					}
					if nt, ok := rt.(*types.Named); ok {
						recv = nt.Obj()
					}
				}
			}
			ast.Inspect(d, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CompositeLit:
					if tv, ok := info.Types[n]; ok && types.Identical(tv.Type, bootType.Type()) && caller != newBoot {
						bad = append(bad, fmt.Sprintf("wiring: %s: bootRecall built outside newBootRecall", fset.Position(n.Pos())))
					}
				case *ast.AssignStmt:
					for _, l := range n.Lhs {
						if s, ok := ast.Unparen(l).(*ast.SelectorExpr); ok && info.Selections[s] != nil {
							if fn, ok := setter[info.Selections[s].Obj()]; ok && fn != caller {
								bad = append(bad, fmt.Sprintf("wiring: %s: %s set outside %s", fset.Position(l.Pos()), s.Sel.Name, fn.Name()))
							}
						}
					}
				case *ast.Ident:
					if r, ok := lookup(info.Uses[n]); ok && !slices.Contains(r.fns, caller) && (r.owner == nil || r.owner != recv) {
						bad = append(bad, fmt.Sprintf("%s: %s: %s reached outside %s", r.req, fset.Position(n.Pos()), n.Name, r.from))
					}
					if info.Uses[n] == wireBoot {
						wireBoots++
					}
				}
				return true
			})
		}
	}
	if wireBoots != 1 {
		bad = append(bad, fmt.Sprintf("JRN-s3-1: wireBootRecall is reached %d times (want 1)", wireBoots))
	}

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
	callsTo := func(e ast.Expr, pkgPath, name string) bool {
		f, _ := callee(info, e).(*types.Func)
		return f != nil && f.Pkg() != nil && f.Pkg().Path() == pkgPath && f.Name() == name
	}
	// The objects main hands bootRecall, pinned to one write each from
	// their source, so they are main's own.
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
			if !ok || len(c.Elts) != 0 {
				return false
			}
			n, ok := info.TypeOf(c).(*types.Named)
			return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "github.com/ghbmrk/agentos/broker/recalltool" && n.Obj().Name() == "LateExecutor"
		}},
		{"lp", "JRN-s3-2", "openLearning", func(e ast.Expr) bool {
			o := pkg.Scope().Lookup("openLearning")
			return o != nil && callee(info, e) == o
		}},
		{"caps", "JRN-s3-3", "newCapState", func(e ast.Expr) bool {
			o := pkg.Scope().Lookup("newCapState")
			return o != nil && callee(info, e) == o
		}},
		{"recallCfg", "JRN-s3-3", "recalltool.ServiceConfig{...}", func(e ast.Expr) bool {
			c, ok := e.(*ast.CompositeLit)
			return ok && isRecallType(info.TypeOf(c), "ServiceConfig")
		}},
		{"recallTools", "JRN-s3-3", "&recalltool.Late{}", func(e ast.Expr) bool {
			u, ok := e.(*ast.UnaryExpr)
			if !ok || u.Op != token.AND {
				return false
			}
			c, ok := u.X.(*ast.CompositeLit)
			return ok && len(c.Elts) == 0 && isRecallType(info.TypeOf(c), "Late")
		}},
		{"forgetBoot", "JRN-s3-1", "wireBootRecall", func(e ast.Expr) bool { return callee(info, e) == wireBoot }},
	} {
		o, why := pinned(p.name, p.src, mainFn, parent, info, p.from)
		if why != "" {
			bad = append(bad, fmt.Sprintf("%s: %s", p.req, why))
		}
		obj[p.name] = o
	}
	lp, boot := obj["lp"], obj["forgetBoot"]
	// forgetBoot is only finish's receiver, and lp.forgetOwner only
	// selected from (never written or copied), so no alias stands in for
	// either.
	if n := usedOnly(mainFn, parent, info, boot, func(use, p ast.Node) bool {
		s, ok := p.(*ast.SelectorExpr)
		return ok && s.X == use && info.Uses[s.Sel] == finishFn
	}); n != nil {
		bad = append(bad, fmt.Sprintf("JRN-s3-1: %s: forgetBoot is used other than to finish", fset.Position(n.Pos())))
	}
	if n := usedOnly(mainFn, parent, info, ownerField, func(use, p ast.Node) bool {
		s, ok := p.(*ast.SelectorExpr)
		return ok && s.X == use
	}); n != nil {
		bad = append(bad, fmt.Sprintf("JRN-s3-2: %s: lp.forgetOwner is used other than selected from", fset.Position(n.Pos())))
	}

	// main may hold no jump, and no return between the wire and a call it
	// vouches for (it returns early, before it, in held mode and after
	// sign-in).
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
	// top is the index in main's body of the statement holding n.
	top := func(n ast.Node) int {
		for ; n != nil; n = parent[n] {
			if parent[n] == mainFn.Body {
				for i, s := range mainFn.Body.List {
					if s == n {
						return i
					}
				}
			}
		}
		return -1
	}

	// The calls the order rests on: the wire (forgetBoot's one write),
	// daemon.Run, finish on forgetBoot, lp.attach on lp, and Store on
	// lp.forgetOwner.agent, each matched by object and receiver.
	var wire ast.Node
	var runs, finishes, attaches, stores []*ast.CallExpr
	onLp := func(e ast.Expr, field types.Object) (ast.Expr, bool) {
		s, ok := ast.Unparen(e).(*ast.SelectorExpr)
		if !ok || info.Selections[s] == nil || info.Selections[s].Obj() != field {
			return nil, false
		}
		return s.X, true
	}
	ast.Inspect(mainFn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == 1 && isDef(info, n.Lhs[0], boot) {
				wire = n
			}
		case *ast.CallExpr:
			s, _ := ast.Unparen(n.Fun).(*ast.SelectorExpr)
			switch {
			case callsTo(n, "github.com/ghbmrk/agentos/broker/daemon", "Run"):
				runs = append(runs, n)
			case s != nil && info.Uses[s.Sel] == finishFn:
				finishes = append(finishes, n)
			case s != nil && info.Uses[s.Sel] == attachFn && isObj(info, s.X, lp):
				attaches = append(attaches, n)
			case s != nil && s.Sel.Name == "Store":
				if a, ok := onLp(s.X, agentField); ok {
					if o, ok := onLp(a, ownerField); ok && isObj(info, o, lp) {
						stores = append(stores, n)
					}
				}
			}
		}
		return true
	})
	if wire == nil || len(runs) != 1 {
		return append(bad, fmt.Sprintf("JRN-s3-2: main wires forgetBoot %v and calls daemon.Run %d times (want once)", wire != nil, len(runs)))
	}
	wired = wire.Pos()
	if why := placed(wire); why != "" {
		bad = append(bad, fmt.Sprintf("JRN-s3-2: %s: the wire does not run in place: %s", fset.Position(wire.Pos()), why))
	}
	if top(wire) >= top(runs[0]) {
		bad = append(bad, fmt.Sprintf("JRN-s3-2: %s: wired after daemon.Run", fset.Position(wire.Pos())))
	}

	// JRN-s3-1: main finishes forgetBoot once, in place.
	if len(finishes) != 1 {
		return append(bad, fmt.Sprintf("JRN-s3-1: main finishes boot setup %d times (want 1)", len(finishes)))
	}
	fin := finishes[0]
	if s := ast.Unparen(fin.Fun).(*ast.SelectorExpr); !isObj(info, s.X, boot) {
		bad = append(bad, fmt.Sprintf("JRN-s3-1: %s: finish is not forgetBoot's", fset.Position(fin.Pos())))
	}
	if why := placed(fin); why != "" {
		bad = append(bad, fmt.Sprintf("JRN-s3-1: %s: finish does not run in place: %s", fset.Position(fin.Pos()), why))
	}
	// Under no condition at all (S14 on #2513): a statement of main's body.
	if st, ok := parent[fin].(*ast.ExprStmt); !ok || parent[st] != mainFn.Body {
		bad = append(bad, fmt.Sprintf("JRN-s3-1: %s: finish is not a statement of main's body", fset.Position(fin.Pos())))
	}

	// JRN-s3-2: lp.attach and lp.forgetOwner.agent.Store each run in place
	// in a statement of main's body before finish's.
	for _, k := range []struct {
		name  string
		calls []*ast.CallExpr
	}{{"lp.attach", attaches}, {"lp.forgetOwner.agent.Store", stores}} {
		ok := false
		for _, c := range k.calls {
			if placed(c) == "" && top(c) < top(fin) {
				ok = true
			}
		}
		if !ok {
			bad = append(bad, fmt.Sprintf("JRN-s3-2: no %s runs in place before finish (%d found)", k.name, len(k.calls)))
		}
	}
	if top(fin) <= top(runs[0]) {
		bad = append(bad, fmt.Sprintf("JRN-s3-2: %s: finish runs before daemon.Run", fset.Position(fin.Pos())))
	}

	// JRN-s3-3: the wire hands bootRecall main's own lp, recallDir,
	// verifier, recallExec and caps, and finish main's recallCfg and
	// recallTools.
	if a, ok := wire.(*ast.AssignStmt); ok && len(a.Rhs) == 1 {
		c, _ := ast.Unparen(a.Rhs[0]).(*ast.CallExpr)
		if c == nil || len(c.Args) != 6 || !isObj(info, c.Args[1], lp) || !isObj(info, c.Args[2], obj["recallDir"]) ||
			!isObj(info, c.Args[3], obj["verifier"]) || !isObj(info, c.Args[4], obj["recallExec"]) || !isObj(info, c.Args[5], obj["caps"]) {
			bad = append(bad, fmt.Sprintf("JRN-s3-3: %s: the wire is not given main's lp, recallDir, verifier, recallExec and caps", fset.Position(wire.Pos())))
		}
	}
	if len(fin.Args) != 2 || !isObj(info, fin.Args[0], obj["recallCfg"]) || !isObj(info, fin.Args[1], obj["recallTools"]) {
		bad = append(bad, fmt.Sprintf("JRN-s3-3: %s: finish is not given main's recallCfg and recallTools", fset.Position(fin.Pos())))
	}
	return bad
}

// isRecallType reports whether t is recalltool's type of that name.
func isRecallType(t types.Type, name string) bool {
	n, ok := t.(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "github.com/ghbmrk/agentos/broker/recalltool" && n.Obj().Name() == name
}

// isDef reports whether e, unparenthesised, is the identifier defining obj.
func isDef(info *types.Info, e ast.Expr, obj types.Object) bool {
	id, ok := ast.Unparen(e).(*ast.Ident)
	return ok && obj != nil && info.Defs[id] == obj
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
