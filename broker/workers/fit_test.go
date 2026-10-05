package workers

// REQ: CAP-1, A15, RES-2

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/budget"
	"github.com/ghbmrk/agentos/broker/vm"
)

type fitOut struct {
	Fit         int    `json:"fit"`
	MemMB       int64  `json:"mem_mb"`
	WorkersLeft int    `json:"workers_left"`
	Why         string `json:"why"`
}

// clock lets a test step past the fit cache.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }
func (c *clock) next()          { c.t = c.t.Add(FitFor) }
func newClock(r *rig) *clock    { c := &clock{time.Now()}; r.tools.Now = c.now; return c }

// N is the smaller of what admission's declared budget and measured free
// memory hold, rounded down to FitStepMB, and what the lineage's worker
// cap leaves (CAP-1).
func TestCAP1FitIsTheSmallerOfDeclaredAndMeasured(t *testing.T) {
	r := newRig(t, 8000)
	clk := newClock(r)
	r.agent("agent", vm.Public)
	declared, measured := int64(3000), int64(1100)
	var measureErr error
	r.tools.Free = func(admission.Class) int64 { return declared }
	r.tools.Avail = func() (int64, error) { return measured, measureErr }
	var f fitOut
	r.must("agent", toolFit, m{}, &f)
	if f.Fit != 1024/DefaultMemMB || f.MemMB != DefaultMemMB || f.WorkersLeft != MaxWorkers {
		t.Fatalf("fit = %+v, want %d from 1100 measured rounded to 1024", f, 1024/DefaultMemMB)
	}
	clk.next()
	measured = 1 << 20
	r.must("agent", toolFit, m{"mem_mb": 500}, &f)
	if f.Fit != 5 { // 3000 declared rounds to 2560
		t.Fatalf("fit at 500 MiB = %+v, want 5", f)
	}
	clk.next()
	declared = 1 << 20
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	r.must("agent", toolFit, m{"mem_mb": MinMemMB}, &f)
	if f.Fit != MaxWorkers-1 || f.WorkersLeft != MaxWorkers-1 {
		t.Fatalf("fit beside one worker = %+v, want the cap's %d", f, MaxWorkers-1)
	}
	// Unreadable measurement: admission's budget alone, and it says so.
	clk.next()
	declared, measureErr = 600, errors.New("no meminfo")
	r.must("agent", toolFit, m{}, &f)
	if f.Fit != 2 || !strings.Contains(f.Why, "declared") {
		t.Fatalf("fit without a measurement = %+v", f)
	}
	// At the floor N may be 0, and the answer says what to do.
	clk.next()
	declared, measureErr = 500, nil
	r.must("agent", toolFit, m{}, &f)
	if f.Fit != 0 || !strings.Contains(f.Why, "sequentially") {
		t.Fatalf("fit with no room = %+v", f)
	}
	if err := r.call("agent", toolFit, m{"mem_mb": 1}, nil); err == nil {
		t.Fatal("fit below the minimum worker size accepted")
	}
}

// worker_fit tells a guest no more than one rounded figure per lineage per
// FitFor: no memory field, the same rounded room for every mem_mb asked
// inside the window, and nothing finer than FitStepMB (security F1 on
// #158, REV-5).
func TestCAP1FitRevealsOnlyACoarseCachedFigure(t *testing.T) {
	r := newRig(t, 8000)
	clk := newClock(r)
	r.agent("agent", vm.Public)
	measured, calls := int64(2047), 0
	r.tools.Avail = func() (int64, error) { calls++; return measured, nil }
	var raw map[string]any
	r.must("agent", toolFit, m{"mem_mb": MinMemMB}, &raw)
	for k := range raw {
		if k != "fit" && k != "mem_mb" && k != "workers_left" && k != "why" {
			t.Errorf("worker_fit answers %q", k)
		}
	}
	var f fitOut
	for mem := int64(MinMemMB); mem <= 1024; mem += 37 {
		measured += 300 // the box changes inside the window
		r.must("agent", toolFit, m{"mem_mb": mem}, &f)
		if want := min(MaxWorkers, int(1536/mem)); f.Fit != want {
			t.Fatalf("fit at %d MiB = %d, want %d from 2047 rounded to 1536", mem, f.Fit, want)
		}
	}
	if calls != 1 {
		t.Fatalf("measured %d times inside one window", calls)
	}
	clk.next()
	measured = 2600
	r.must("agent", toolFit, m{"mem_mb": 512}, &f)
	if f.Fit != 5 || calls != 2 {
		t.Fatalf("after the window fit = %d (%d measurements), want 5 from 2560", f.Fit, calls)
	}
	// Another lineage gets its own window, not this one's figure.
	r.agent("b", vm.Public)
	measured = 700
	r.must("b", toolFit, m{"mem_mb": 512}, &f)
	if f.Fit != 1 {
		t.Fatalf("lineage b fit = %d, want 1 from 700 rounded to 512", f.Fit)
	}
}

// The tool asks admission for the caller's own class: an experiment sees
// only free budget, accepted work also what it may preempt (RES-2).
func TestCAP1FitAsksForTheCallersClass(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public) // admission.Experiment
	var got []admission.Class
	r.tools.Free = func(c admission.Class) int64 { got = append(got, c); return 1000 }
	r.must("agent", toolFit, m{}, nil)
	if len(got) != 1 || got[0] != admission.Experiment {
		t.Fatalf("fit asked for classes %v, want the caller's experiment class", got)
	}
}

// up_to_fit forks only as many as fit and names the rest (CAP-1).
func TestCAP1ForkUpToFit(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	clk := newClock(r)
	r.must("agent", toolCreate, m{"name": "src", "mem_mb": FitStepMB}, nil)
	r.tools.Avail = func() (int64, error) { return 3*FitStepMB + 100, nil }
	var out struct {
		Workers []string
		Skipped []string
	}
	r.must("agent", toolFork, m{"name": "src", "into": []string{"a", "b", "c", "d", "e"}, "up_to_fit": true}, &out)
	if fmt.Sprint(out.Workers) != "[a b c]" || fmt.Sprint(out.Skipped) != "[d e]" {
		t.Fatalf("fork up to fit = %+v", out)
	}
	clk.next()
	r.tools.Avail = func() (int64, error) { return 0, nil }
	err := r.call("agent", toolFork, m{"name": "src", "into": []string{"f"}, "up_to_fit": true}, nil)
	if err == nil || !strings.Contains(err.Error(), "no fork fits") {
		t.Fatalf("fork with no room: %v", err)
	}
	// Without up_to_fit the fork is all or nothing, as before.
	r.tools.Avail = nil
	r.must("agent", toolFork, m{"name": "src", "into": []string{"g", "h"}}, nil)
}

// worker_keep keeps the winner and destroys its fork siblings, and only
// those: the source and other workers stay (CAP-1, A15).
func TestCAP1KeepTheWinnerDiscardsTheRest(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "src"}, nil)
	r.must("agent", toolCreate, m{"name": "other"}, nil)
	r.must("agent", toolFork, m{"name": "src", "into": []string{"t1", "t2", "t3"}}, nil)
	var out struct {
		Kept      string
		Destroyed []string
	}
	r.must("agent", toolKeep, m{"name": "t2"}, &out)
	if out.Kept != "t2" || fmt.Sprint(out.Destroyed) != "[t1 t3]" {
		t.Fatalf("keep = %+v", out)
	}
	var l struct{ Workers []struct{ Name string } }
	r.must("agent", toolList, m{}, &l)
	var names []string
	for _, w := range l.Workers {
		names = append(names, w.Name)
	}
	if fmt.Sprint(names) != "[other src t2]" {
		t.Fatalf("after keep: %v", names)
	}
	if err := r.call("agent", toolKeep, m{"name": "src"}, nil); err == nil || !strings.Contains(err.Error(), "not a fork") {
		t.Fatalf("keep of an unforked worker: %v", err)
	}
	// Another lineage's forks are never touched.
	r.agent("b", vm.Public)
	r.must("b", toolCreate, m{"name": "src"}, nil)
	r.must("b", toolFork, m{"name": "src", "into": []string{"x", "y"}}, nil)
	r.must("agent", toolFork, m{"name": "src", "into": []string{"u1", "u2"}}, nil)
	r.must("agent", toolKeep, m{"name": "u1"}, nil)
	r.must("b", toolList, m{}, &l)
	if len(l.Workers) != 3 {
		t.Fatalf("keep in one lineage destroyed another's workers: %+v", l)
	}
}

// Smaller workers fit more, and fit says how many from the same rounded,
// cached room (potency on #158, keeping security F1).
func TestCAP1FitSaysSmallerWorkersFitMore(t *testing.T) {
	floor, err := budget.ForHost(7680, 4, budget.Floor())
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, floor.PoolMB)
	clk := newClock(r)
	if _, err := r.m.Create(context.Background(), "agent", vm.Spec{Image: "base", Class: admission.Foreground, MemMB: budget.OpenClawMB}); err != nil {
		t.Fatal(err)
	}
	r.tools.Free = func(admission.Class) int64 { return r.adm.Snapshot().FreeMB }
	var f fitOut
	r.must("agent", toolFit, m{}, &f) // 1944 free rounds to 1536
	if f.Fit != 6 || !strings.Contains(f.Why, "smaller workers fit more: 8 at 192 MB") {
		t.Fatalf("fit at the default on the floor = %+v", f)
	}
	measured := int64(1500) // 7 at 192 unrounded; 1024 rounded holds 5
	r.tools.Avail = func() (int64, error) { return measured, nil }
	clk.next()
	r.must("agent", toolFit, m{"mem_mb": 512}, &f)
	if f.Fit != 2 || !strings.Contains(f.Why, "5 at 192 MB") {
		t.Fatalf("fit at 512 = %+v, want 2 and 5 at 192 from 1024", f)
	}
	measured = 100
	r.must("agent", toolFit, m{"mem_mb": 512}, &f) // cached: still 1024
	if !strings.Contains(f.Why, "5 at 192 MB") {
		t.Fatalf("smaller count measured inside the window: %+v", f)
	}
	for _, mem := range []int64{SmallMemMB, MinMemMB} {
		f = fitOut{} // why is omitted when empty
		r.must("agent", toolFit, m{"mem_mb": mem}, &f)
		if strings.Contains(f.Why, "smaller") {
			t.Fatalf("fit at %d MiB offers smaller workers: %+v", mem, f)
		}
	}
	// No hint when the worker cap, not memory, binds.
	clk.next()
	measured = 1 << 20
	r.tools.Free = func(admission.Class) int64 { return 1 << 20 }
	f = fitOut{}
	r.must("agent", toolFit, m{"mem_mb": 512}, &f)
	if f.Fit != MaxWorkers || strings.Contains(f.Why, "smaller") {
		t.Fatalf("fit with room for all = %+v", f)
	}
	var create string
	for _, tl := range r.tools.List() {
		if tl["name"] == toolCreate {
			create = tl["description"].(string)
		}
	}
	if !strings.Contains(create, "7 fit beside you at 256 MiB, 8 at 192 MiB") {
		t.Fatalf("worker_create does not say smaller workers fit more: %q", create)
	}
}

// A15WorkerMB is a worker size at which A15's 8 forks fit beside the
// agent on the floor host: (3496 - 1552 - 192) rounds to 1536 = 8 x 192.
const A15WorkerMB = 192

// A15's shape within RES-2: on the floor host's pool beside the agent, one
// guest asks how many fit, forks 8, tests each, and keeps the winner;
// admission never goes over its budget.
func TestA15EightWorkersWithinRES2(t *testing.T) {
	// The floor host's pool (8 GB, 4 cores; potency R1 on #158).
	floor, err := budget.ForHost(7680, 4, budget.Floor())
	if err != nil {
		t.Fatal(err)
	}
	r := newRig(t, floor.PoolMB)
	if _, err := r.m.Create(context.Background(), "agent", vm.Spec{Image: "base", Class: admission.Foreground, MemMB: budget.OpenClawMB}); err != nil {
		t.Fatal(err)
	}
	r.tools.Free = func(admission.Class) int64 { return r.adm.Snapshot().FreeMB }
	// At the default 256 MiB only 6 forks fit here (3496 - 1552 - 256 =
	// 1688, rounded to 1536): the guest sizes its workers to the count
	// it wants, which K16 records.
	r.must("agent", toolCreate, m{"name": "src", "mem_mb": A15WorkerMB}, nil)
	r.must("agent", toolWrite, m{"name": "src", "path": "/task", "content": "solve"}, nil)
	var f fitOut
	r.must("agent", toolFit, m{"mem_mb": A15WorkerMB}, &f)
	if f.Fit < 8 {
		t.Fatalf("only %d workers of %d MiB fit on the floor's pool, A15 needs 8", f.Fit, A15WorkerMB)
	}
	var into []string
	for i := range 8 {
		into = append(into, fmt.Sprintf("try%d", i))
	}
	var forked struct{ Workers []string }
	r.must("agent", toolFork, m{"name": "src", "into": into, "up_to_fit": true}, &forked)
	if len(forked.Workers) != 8 {
		t.Fatalf("forked %v, want 8", forked.Workers)
	}
	if free := r.adm.Snapshot().FreeMB; free < 0 {
		t.Fatalf("admission over budget: %d MB free", free)
	}
	for i, n := range forked.Workers {
		r.must("agent", toolWrite, m{"name": n, "path": "/answer", "content": fmt.Sprint(i)}, nil)
		var ex execOut
		r.must("agent", toolExec, m{"name": n, "argv": []string{"cat", "/task"}}, &ex)
		if ex.Stdout != "solve" {
			t.Fatalf("%s sees %q", n, ex.Stdout)
		}
	}
	r.must("agent", toolKeep, m{"name": "try5"}, nil)
	var read struct{ Content string }
	r.must("agent", toolRead, m{"name": "try5", "path": "/answer"}, &read)
	if read.Content != "5" {
		t.Fatalf("the winner holds %q", read.Content)
	}
	if n := len(r.adm.Snapshot().Running); n != 3 { // agent, src, winner
		t.Fatalf("%d machines admitted after keep, want 3", n)
	}
}

// keep and destroy read the machine table, not a worker's lock: a command
// running in the winner, a sibling or an unrelated worker does not hold
// them up, and destroy ends a sibling's command (L3 MUST-1 on #158, K11).
func TestCAP1KeepAndDestroyDoNotWaitBehindACommand(t *testing.T) {
	r := newRig(t, 16000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "src", "mem_mb": MinMemMB}, nil)
	r.must("agent", toolCreate, m{"name": "other", "mem_mb": MinMemMB}, nil)
	r.must("agent", toolFork, m{"name": "src", "into": []string{"a", "b", "c"}}, nil)
	ran := make(chan error, 3)
	for _, n := range []string{"a", "b", "other"} {
		go func() {
			ran <- r.call("agent", toolExec, m{"name": n, "argv": []string{"sleep"}, "timeout_seconds": 600}, nil)
		}()
	}
	time.Sleep(20 * time.Millisecond) // the commands hold their workers
	done := make(chan struct{})
	var kept struct {
		Kept      string
		Destroyed []string
	}
	go func() {
		defer close(done)
		r.must("agent", toolKeep, m{"name": "a"}, &kept)
		r.must("agent", toolDestroy, m{"name": "other"}, nil)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("keep or destroy waited behind a worker's command")
	}
	if kept.Kept != "a" || fmt.Sprint(kept.Destroyed) != "[b c]" {
		t.Fatalf("keep = %+v", kept)
	}
	<-ran // b's and other's commands end with their workers
	<-ran
	mc, _ := r.m.Get("agent")
	if err := r.m.Destroy(context.Background(), workerID(mc.Lineage, "a")); err != nil {
		t.Fatal(err)
	}
	<-ran
}

// A fork still starting has no fork base yet, so keep refuses rather than
// miss it (L3 SHOULD-5 on #158).
func TestCAP1KeepWaitsForStartingForks(t *testing.T) {
	r := newRig(t, 16000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "src", "mem_mb": MinMemMB}, nil)
	r.must("agent", toolFork, m{"name": "src", "into": []string{"a", "b"}}, nil)
	h := hold{r.m, make(chan struct{}), make(chan struct{})}
	r.tools.M = h
	forked := make(chan error, 1)
	go func() { forked <- r.call("agent", toolFork, m{"name": "a", "into": []string{"late"}}, nil) }()
	<-h.forking
	if err := r.call("agent", toolKeep, m{"name": "b"}, nil); err == nil || err.Error() != "some of your workers are still starting; keep the winner once worker_create or worker_fork returns" {
		t.Fatalf("keep beside a starting fork: %v", err)
	}
	close(h.release)
	if err := <-forked; err != nil {
		t.Fatal(err)
	}
	var kept struct{ Destroyed []string }
	r.must("agent", toolKeep, m{"name": "b"}, &kept)
	if fmt.Sprint(kept.Destroyed) != "[a]" {
		t.Fatalf("keep after the fork = %+v", kept)
	}
}

// A foreground agent's workers run as accepted work: they yield to memory
// pressure and never outrank the owner's foreground machines. fit asks
// for that class, and a fork's fit for the worker's own class (L3
// SHOULD-1, SHOULD-2 on #158).
func TestCAP1WorkersRunAsAcceptedWorkAtMost(t *testing.T) {
	r := newRig(t, 16000)
	ag, err := r.m.Create(context.Background(), "agent", vm.Spec{Image: "base", Class: admission.Foreground, MemMB: 500})
	if err != nil {
		t.Fatal(err)
	}
	var asked []admission.Class
	r.tools.Free = func(c admission.Class) int64 { asked = append(asked, c); return 1 << 20 }
	r.must("agent", toolFit, m{}, nil)
	r.must("agent", toolCreate, m{"name": "w", "mem_mb": MinMemMB}, nil)
	w, _ := r.m.Get(workerID(ag.Lineage, "w"))
	if w.Spec.Class != admission.Accepted || fmt.Sprint(asked) != fmt.Sprint([]admission.Class{admission.Accepted}) {
		t.Fatalf("worker class %v, fit asked %v; want accepted", w.Spec.Class, asked)
	}
	// A worker of another class in the lineage: its fork is sized for it.
	if _, err := r.m.CreateWorker(context.Background(), workerID(ag.Lineage, "exp"), ag.Lineage, vm.Spec{Image: "base", Class: admission.Experiment, MemMB: MinMemMB}); err != nil {
		t.Fatal(err)
	}
	asked = nil
	r.must("agent", toolFork, m{"name": "exp", "into": []string{"e1"}, "up_to_fit": true}, nil)
	if fmt.Sprint(asked) != fmt.Sprint([]admission.Class{admission.Experiment}) {
		t.Fatalf("fork's fit asked %v, want the worker's experiment class", asked)
	}
	// An experiment agent's workers stay experiments.
	r.agent("exp-agent", vm.Public)
	r.must("exp-agent", toolCreate, m{"name": "w", "mem_mb": MinMemMB}, nil)
	ea, _ := r.m.Get("exp-agent")
	if w, _ := r.m.Get(workerID(ea.Lineage, "w")); w.Spec.Class != admission.Experiment {
		t.Fatalf("experiment agent's worker class %v", w.Spec.Class)
	}
}

// making reports pending as already in the manager's table, as Workers
// does for a worker the manager is still making.
type making struct {
	*vm.Manager
	extra string
}

func (k making) Workers(l string) []string { return append(k.Manager.Workers(l), k.extra) }

// A worker being made sits in both the manager's table and the pending
// reservations; it counts once (L3 SHOULD-4 on #158). A negative
// measurement reads as no room, not as unbounded (SHOULD-7).
func TestCAP1FitCountsAWorkerBeingMadeOnce(t *testing.T) {
	r := newRig(t, 16000)
	clk := newClock(r)
	ag := r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w", "mem_mb": MinMemMB}, nil)
	id := workerID(ag.Lineage, "being-made")
	r.tools.M = making{r.m, id}
	r.tools.pending = map[string]string{id: ag.Lineage}
	var f fitOut
	r.must("agent", toolFit, m{"mem_mb": MinMemMB}, &f)
	if f.WorkersLeft != MaxWorkers-2 {
		t.Fatalf("workers_left = %d, want %d", f.WorkersLeft, MaxWorkers-2)
	}
	clk.next()
	r.tools.Avail = func() (int64, error) { return -600, nil }
	f = fitOut{}
	r.must("agent", toolFit, m{"mem_mb": MinMemMB}, &f)
	if f.Fit != 0 {
		t.Fatalf("fit with a negative measurement = %+v", f)
	}
}

// up_to_fit sizes the fork by the source worker's own memory, whatever
// it is (L3 SHOULD-3 on #158).
func TestCAP1ForkUpToFitUsesTheWorkersSize(t *testing.T) {
	r := newRig(t, 16000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "src", "mem_mb": 384}, nil)
	r.tools.Avail = func() (int64, error) { return 1600, nil } // rounds to 1536: 4 at 384
	var out struct{ Workers, Skipped []string }
	r.must("agent", toolFork, m{"name": "src", "into": []string{"a", "b", "c", "d", "e", "f", "g"}, "up_to_fit": true}, &out)
	if fmt.Sprint(out.Workers) != "[a b c d]" || fmt.Sprint(out.Skipped) != "[e f g]" {
		t.Fatalf("fork of a 384 MiB worker = %+v", out)
	}
}

// failDestroy refuses to destroy one machine.
type failDestroy struct {
	*vm.Manager
	id string
}

func (f failDestroy) Destroy(ctx context.Context, id string) error {
	if id == f.id {
		return errors.New("disk busy")
	}
	return f.Manager.Destroy(ctx, id)
}

// A keep that fails part way says which siblings already went, since a
// failed call carries no answer (L3 SHOULD-8 on #158).
func TestCAP1KeepSaysWhatWentBeforeAnError(t *testing.T) {
	r := newRig(t, 16000)
	ag := r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "src", "mem_mb": MinMemMB}, nil)
	r.must("agent", toolFork, m{"name": "src", "into": []string{"a", "b", "c", "d"}}, nil)
	r.tools.M = failDestroy{r.m, workerID(ag.Lineage, "c")}
	err := r.call("agent", toolKeep, m{"name": "a"}, nil)
	// The cause goes to the broker's log; the guest gets its ref (SR2-3f).
	if err == nil || !regexp.MustCompile(`^worker c: failed \(ref [0-9a-f]{8}\); the broker's log has the detail \(already destroyed: b\)$`).MatchString(err.Error()) {
		t.Fatalf("keep with a failed destroy: %v", err)
	}
}

// The guest sees "preempted, retry", not an exit code, when its worker is
// preempted mid-command (potency R1 on #158).
func TestCAP1PreemptedCommandSaysRetry(t *testing.T) {
	r := newRig(t, 16000)
	ag := r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w", "mem_mb": MinMemMB}, nil)
	done := make(chan error, 1)
	go func() {
		done <- r.call("agent", toolExec, m{"name": "w", "argv": []string{"sleep"}, "timeout_seconds": 600}, nil)
	}()
	time.Sleep(20 * time.Millisecond)
	if err := r.m.Preempt(workerID(ag.Lineage, "w")); err != nil {
		t.Fatal(err)
	}
	err := <-done
	// The preemption found the worker busy: it records it, writing the
	// machine's files, once the command lets go. Get takes the same lock,
	// so Preempted is seen only after that write; the test must not
	// return (and remove its directory) before.
	for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if w, _ := r.m.Get(workerID(ag.Lineage, "w")); w.State == vm.Preempted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the preemption never finished")
		}
	}
	if err == nil || !strings.HasPrefix(err.Error(), "preempted, retry: worker w ") || !strings.Contains(err.Error(), "did not fail") || !strings.Contains(err.Error(), "destroy and recreate it") {
		t.Fatalf("preempted exec = %v", err)
	}
}

// goneDestroy reports one machine as already gone.
type goneDestroy struct {
	*vm.Manager
	id string
}

func (g goneDestroy) Destroy(ctx context.Context, id string) error {
	if id == g.id {
		return fmt.Errorf("%w: machine %s", vm.ErrUnknown, id)
	}
	return g.Manager.Destroy(ctx, id)
}

// A sibling destroyed meanwhile counts as gone, not as a failed keep (L3
// nit 2 on #158).
func TestCAP1KeepSkipsASiblingAlreadyGone(t *testing.T) {
	r := newRig(t, 16000)
	ag := r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "src", "mem_mb": MinMemMB}, nil)
	r.must("agent", toolFork, m{"name": "src", "into": []string{"a", "b", "c", "d"}}, nil)
	r.tools.M = goneDestroy{r.m, workerID(ag.Lineage, "c")}
	var kept struct{ Destroyed []string }
	r.must("agent", toolKeep, m{"name": "a"}, &kept)
	if fmt.Sprint(kept.Destroyed) != "[b d]" {
		t.Fatalf("keep beside a vanished sibling = %+v", kept)
	}
}
