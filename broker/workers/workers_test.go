package workers

// REQ: CAP-8, REV-5, A14, A15

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// runtime stands in for gVisor: a guest's files are its upper layer, its
// memory a checkpointed marker. Exec understands cat, tee, echo and sleep
// (until cancelled).
type runtime struct {
	mu      sync.Mutex
	running map[string]vm.Launch
}

func (r *runtime) Start(_ context.Context, l vm.Launch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running[l.ID] = l
	return nil
}
func (r *runtime) Restore(ctx context.Context, l vm.Launch, _ string) error { return r.Start(ctx, l) }
func (r *runtime) Pause(context.Context, string) error                      { return nil }
func (r *runtime) Resume(context.Context, string) error                     { return nil }
func (r *runtime) Checkpoint(_ context.Context, _, image string) error {
	return os.WriteFile(filepath.Join(image, "mem"), []byte("m"), 0o600)
}
func (r *runtime) Kill(_ context.Context, l vm.Launch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, l.ID)
	return nil
}
func (r *runtime) Exec(ctx context.Context, id string, c vm.Command) (vm.ExecResult, error) {
	r.mu.Lock()
	l, ok := r.running[id]
	r.mu.Unlock()
	if !ok {
		return vm.ExecResult{}, fmt.Errorf("%s not running", id)
	}
	a := c.Argv
	path := func() string { return filepath.Join(l.Upper, strings.TrimPrefix(a[len(a)-1], "/")) }
	switch a[0] {
	case "sleep":
		<-ctx.Done()
		return vm.ExecResult{}, ctx.Err()
	case "echo":
		return vm.ExecResult{Stdout: []byte(strings.Join(a[1:], " "))}, nil
	case "stdin":
		return vm.ExecResult{Stdout: c.Stdin}, nil
	case "cat", "tail":
		b, err := os.ReadFile(path())
		if err != nil {
			return vm.ExecResult{ExitCode: 1, Stderr: []byte("no such file")}, nil
		}
		if a[0] == "tail" { // tail -c +N -- PATH
			var n int
			fmt.Sscanf(a[2], "+%d", &n)
			b = b[min(n-1, len(b)):]
		}
		r := vm.ExecResult{Stdout: b}
		if c.MaxOutput > 0 && len(b) > c.MaxOutput {
			r.Stdout, r.Truncated = b[:c.MaxOutput], true
		}
		return r, nil
	case "tee":
		os.MkdirAll(filepath.Dir(path()), 0o755)
		return vm.ExecResult{}, os.WriteFile(path(), c.Stdin, 0o644)
	}
	return vm.ExecResult{ExitCode: 127}, nil
}

type rig struct {
	t     *testing.T
	m     *vm.Manager
	tools *Tools
}

type late struct{ m **vm.Manager }

func (l late) Preempt(id string) error { return (*l.m).Preempt(id) }

func newRig(t *testing.T, capacityMB int64) *rig {
	r := &rig{t: t}
	adm, err := admission.New(admission.Config{CapacityMB: capacityMB}, late{&r.m})
	if err != nil {
		t.Fatal(err)
	}
	img := t.TempDir()
	r.m, err = vm.Open(context.Background(), vm.Config{
		StateDir: filepath.Join(t.TempDir(), "state"), Images: map[string]string{"base": img},
		Runtime: &runtime{running: map[string]vm.Launch{}}, Admit: adm, NoCgroups: true,
		FreeBytes: func(string) (int64, error) { return 1 << 50, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	r.tools = &Tools{M: r.m, Image: "base", Argv: []string{"idle"}, MaxMemMB: 2048}
	return r
}

func (r *rig) agent(id string, l vm.Label) vm.Machine {
	r.t.Helper()
	m, err := r.m.Create(context.Background(), id, vm.Spec{Image: "base", Class: admission.Experiment, MemMB: 500, Label: l})
	if err != nil {
		r.t.Fatal(err)
	}
	return m
}

// call runs tool for machine and decodes its JSON answer into out.
func (r *rig) call(machine, tool string, args any, out any) error {
	r.t.Helper()
	mc, err := r.m.Get(machine)
	if err != nil {
		r.t.Fatal(err)
	}
	b, _ := json.Marshal(args)
	text, handled, err := r.tools.Call(context.Background(), machine, mc.Lineage, tool, b)
	if !handled {
		r.t.Fatalf("%s not handled", tool)
	}
	if err == nil && out != nil {
		if jerr := json.Unmarshal([]byte(text), out); jerr != nil {
			r.t.Fatalf("%s answered %q: %v", tool, text, jerr)
		}
	}
	return err
}

func (r *rig) must(machine, tool string, args any, out any) {
	r.t.Helper()
	if err := r.call(machine, tool, args, out); err != nil {
		r.t.Fatalf("%s: %v", tool, err)
	}
}

type m = map[string]any

// A15's shape: one guest drives workers through fork, test and keep the
// winner: write, run, checkpoint, fork, diff, roll back, destroy.
func TestCAP8GuestDrivesWorkersThroughForkTestAndKeep(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	var created struct {
		Label string `json:"label"`
		MemMB int64  `json:"mem_mb"`
	}
	r.must("agent", toolCreate, m{"name": "base", "mem_mb": 256}, &created)
	if created.Label != "public" || created.MemMB != 256 {
		t.Fatalf("create = %+v", created)
	}
	r.must("agent", toolWrite, m{"name": "base", "path": "/src/app.py", "content": "v1"}, nil)
	var snap struct{ Snapshot string }
	r.must("agent", toolCkpt, m{"name": "base"}, &snap)
	var forked struct{ Snapshot string }
	r.must("agent", toolFork, m{"name": "base", "into": []string{"try1", "try2"}}, &forked)
	r.must("agent", toolWrite, m{"name": "try1", "path": "/src/app.py", "content": "v2"}, nil)
	var read struct{ Content string }
	r.must("agent", toolRead, m{"name": "try1", "path": "/src/app.py"}, &read)
	if read.Content != "v2" {
		t.Fatalf("read try1 = %q", read.Content)
	}
	r.must("agent", toolRead, m{"name": "try2", "path": "/src/app.py"}, &read)
	if read.Content != "v1" {
		t.Fatalf("fork try2 lost the file: %q", read.Content)
	}
	var winner struct{ Snapshot string }
	r.must("agent", toolCkpt, m{"name": "try1"}, &winner)
	var d struct {
		Changes []struct{ Path, Op string }
		Total   int
	}
	r.must("agent", toolDiff, m{"a": snap.Snapshot, "b": winner.Snapshot}, &d)
	if d.Total != 1 || d.Changes[0].Path != "src/app.py" || d.Changes[0].Op != "modified" {
		t.Fatalf("diff = %+v", d)
	}
	var ex execOut
	r.must("agent", toolExec, m{"name": "try1", "argv": []string{"echo", "tests", "pass"}}, &ex)
	if ex.Stdout != "tests pass" || ex.ExitCode != 0 {
		t.Fatalf("exec = %+v", ex)
	}
	r.must("agent", toolDestroy, m{"name": "try2"}, nil)
	r.must("agent", toolRollback, m{"name": "try1", "snapshot": forked.Snapshot}, nil)
	r.must("agent", toolRead, m{"name": "try1", "path": "/src/app.py"}, &read)
	if read.Content != "v1" {
		t.Fatalf("rollback left %q", read.Content)
	}
	var l struct {
		Workers []struct{ Name, State, Label string }
	}
	r.must("agent", toolList, m{}, &l)
	if len(l.Workers) != 2 {
		t.Fatalf("list = %+v", l)
	}
}

// A15 at the floor shape: eight workers at once, within admission; past
// the lineage's cap, no more.
func TestCAP8EightWorkersRunAndTheCapHolds(t *testing.T) {
	r := newRig(t, 64<<10)
	r.agent("agent", vm.Public)
	for i := 0; i < MaxWorkers; i++ {
		r.must("agent", toolCreate, m{"name": fmt.Sprint("w", i), "mem_mb": 64}, nil)
	}
	if err := r.call("agent", toolCreate, m{"name": "extra", "mem_mb": 64}, nil); err == nil {
		t.Fatal("created more workers than the cap")
	}
}

// RES-2: admission sizes how many run.
func TestCAP8AdmissionRefusesAWorkerWithNoRoom(t *testing.T) {
	r := newRig(t, 1000)
	r.agent("agent", vm.Public)
	if err := r.call("agent", toolCreate, m{"name": "big", "mem_mb": 2000}, nil); err == nil {
		t.Fatal("a worker over the box's capacity started")
	}
	if err := r.call("agent", toolCreate, m{"name": "huge", "mem_mb": 1 << 20}, nil); err == nil {
		t.Fatal("a worker over the per-worker cap was asked of admission")
	}
}

// REV-5 and A14: a private machine's worker is private; a private machine
// writing into a public worker raises it, after which the lineage's public
// machine cannot read it.
func TestA14WorkerLabelsFollowTheirWriters(t *testing.T) {
	r := newRig(t, 8000)
	pub := r.agent("agent", vm.Public)
	// A private fork of the agent shares its lineage.
	if _, err := r.m.Fork(context.Background(), "agent", []string{"agent-priv"}); err != nil {
		t.Fatal(err)
	}
	if err := r.m.RaiseLabel("agent-priv", vm.Private); err != nil {
		t.Fatal(err)
	}
	var created struct{ Label string }
	r.must("agent-priv", toolCreate, m{"name": "mine"}, &created)
	if created.Label != "private" {
		t.Fatalf("private machine's worker is %s", created.Label)
	}
	if err := r.call("agent", toolRead, m{"name": "mine", "path": "/x"}, nil); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("public machine read a private worker: %v", err)
	}

	r.must("agent", toolCreate, m{"name": "shared"}, &created)
	r.must("agent", toolWrite, m{"name": "shared", "path": "/out", "content": "public"}, nil)
	r.must("agent-priv", toolWrite, m{"name": "shared", "path": "/out", "content": "owner data"}, nil)
	w, err := r.m.Get(workerID(pub.Lineage, "shared"))
	if err != nil || w.Label != vm.Private {
		t.Fatalf("worker written by a private machine is %v (%v)", w.Label, err)
	}
	for _, c := range []struct {
		tool string
		args m
	}{
		{toolRead, m{"name": "shared", "path": "/out"}},
		{toolExec, m{"name": "shared", "argv": []string{"cat", "/out"}}},
		{toolFork, m{"name": "shared", "into": []string{"leak"}}},
	} {
		if err := r.call("agent", c.tool, c.args, nil); err == nil {
			t.Errorf("%s: public machine reached a private worker", c.tool)
		}
	}
	var snap struct{ Snapshot string }
	r.must("agent-priv", toolCkpt, m{"name": "shared"}, &snap)
	if err := r.call("agent", toolDiff, m{"a": snap.Snapshot, "b": snap.Snapshot}, nil); err == nil {
		t.Error("public machine diffed a private snapshot")
	}
}

// Only the lineage that made a worker can name it or its snapshots, and a
// worker cannot drive workers.
func TestCAP8WorkersBelongToTheirLineage(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("a", vm.Public)
	r.agent("b", vm.Public)
	r.must("a", toolCreate, m{"name": "w"}, nil)
	var snap struct{ Snapshot string }
	r.must("a", toolCkpt, m{"name": "w"}, &snap)
	if err := r.call("b", toolExec, m{"name": "w", "argv": []string{"echo"}}, nil); err == nil || err.Error() != errNoWorker.Error() {
		t.Fatalf("another lineage reached the worker: %v", err)
	}
	if err := r.call("b", toolDiff, m{"a": snap.Snapshot, "b": snap.Snapshot}, nil); err == nil {
		t.Fatal("another lineage diffed the worker's snapshot")
	}
	r.must("b", toolCreate, m{"name": "w"}, nil) // same name, its own worker
	var la, lb struct{ Workers []struct{ Name string } }
	r.must("a", toolList, m{}, &la)
	r.must("b", toolList, m{}, &lb)
	if len(la.Workers) != 1 || len(lb.Workers) != 1 {
		t.Fatalf("lists = %+v, %+v", la, lb)
	}
	// The agent's own snapshots are not worker snapshots.
	own, err := r.m.Checkpoint(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.call("a", toolRollback, m{"name": "w", "snapshot": own.ID}, nil); err == nil {
		t.Fatal("rolled a worker back to its creator's snapshot")
	}
	wid := workerID(func() string { mc, _ := r.m.Get("a"); return mc.Lineage }(), "w")
	if _, handled, err := r.tools.Call(context.Background(), wid, "x", toolList, nil); !handled || err == nil {
		t.Fatal("a worker drove workers")
	}
}

func TestCAP8ArgumentsAreBounded(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	for _, c := range []struct {
		tool string
		args m
	}{
		{toolCreate, m{"name": "Bad_Name"}},
		{toolCreate, m{"name": "w2", "mem_mb": 1}},
		{toolExec, m{"name": "w", "argv": []string{}}},
		{toolExec, m{"name": "w", "argv": make([]string, MaxArgs+1)}},
		{toolExec, m{"name": "w", "argv": []string{"echo"}, "stdin": strings.Repeat("x", MaxStdin+1)}},
		{toolRead, m{"name": "w", "path": "relative"}},
		{toolWrite, m{"name": "w", "path": "/f", "content": strings.Repeat("x", MaxStdin+1)}},
		{toolFork, m{"name": "w", "into": []string{}}},
	} {
		if err := r.call("agent", c.tool, c.args, nil); err == nil {
			t.Errorf("%s %v accepted", c.tool, c.args)
		}
	}
	if _, handled, _ := r.tools.Call(context.Background(), "agent", "x", "effect_request", nil); handled {
		t.Fatal("worker tools claimed another tool's name")
	}
}

// UX-146-1: an idle worker, or one whose creator has stopped, is parked
// (checkpointed and stopped) and revives by rollback to its snapshot.
func TestCAP8IdleAndOrphanedWorkersAreParkedAndRevive(t *testing.T) {
	r := newRig(t, 8000)
	now := time.Now()
	r.tools.Now = func() time.Time { return now }
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "busy"}, nil)
	r.must("agent", toolCreate, m{"name": "idle"}, nil)
	r.must("agent", toolWrite, m{"name": "idle", "path": "/f", "content": "kept"}, nil)

	now = now.Add(IdleAfter - time.Minute)
	r.must("agent", toolExec, m{"name": "busy", "argv": []string{"echo"}}, nil)
	now = now.Add(2 * time.Minute)
	parked := r.tools.Reap(context.Background())
	if len(parked) != 1 || !strings.HasSuffix(parked[0], "-idle") {
		t.Fatalf("parked %v, want only the idle worker", parked)
	}
	var l struct {
		Workers []struct{ Name, State, Snapshot string }
	}
	r.must("agent", toolList, m{}, &l)
	var snap string
	for _, w := range l.Workers {
		if w.Name == "idle" {
			if w.State != "stopped" || w.Snapshot == "" {
				t.Fatalf("parked worker listed as %+v", w)
			}
			snap = w.Snapshot
		}
	}
	r.must("agent", toolRollback, m{"name": "idle", "snapshot": snap}, nil)
	var read struct{ Content string }
	r.must("agent", toolRead, m{"name": "idle", "path": "/f"}, &read)
	if read.Content != "kept" {
		t.Fatalf("revived worker lost its file: %q", read.Content)
	}

	// The creator stops: its workers park at once.
	if err := r.m.Destroy(context.Background(), "agent"); err != nil {
		t.Fatal(err)
	}
	if parked := r.tools.Reap(context.Background()); len(parked) != 2 {
		t.Fatalf("with the creator gone, parked %v, want both workers", parked)
	}
}

// UX-146-2: a refusal for want of room says what works.
func TestCAP8NoRoomSaysWhatToDo(t *testing.T) {
	r := newRig(t, 1000)
	r.agent("agent", vm.Public)
	err := r.call("agent", toolCreate, m{"name": "big", "mem_mb": 1024}, nil)
	if err == nil || !strings.Contains(err.Error(), "destroy a worker, or ask for less memory") {
		t.Fatalf("refusal = %v", err)
	}
}

// interleave runs before between the tools' checks and the manager's
// Exec, as another machine's call would.
type interleave struct {
	*vm.Manager
	before func()
}

func (i interleave) Exec(ctx context.Context, id string, c vm.Command, timeout time.Duration) (vm.ExecResult, error) {
	i.before()
	return i.Manager.Exec(ctx, id, c, timeout)
}

// A private machine's write that lands between a public machine's checks
// and its command does not reach the public machine: the label is checked
// again under the worker's lock (L3 MUST-2 on #146).
func TestREV5PrivateWriteBetweenCheckAndCommandIsNotRead(t *testing.T) {
	r := newRig(t, 8000)
	pub := r.agent("agent", vm.Public)
	if _, err := r.m.Fork(context.Background(), "agent", []string{"agent-priv"}); err != nil {
		t.Fatal(err)
	}
	if err := r.m.RaiseLabel("agent-priv", vm.Private); err != nil {
		t.Fatal(err)
	}
	r.must("agent", toolCreate, m{"name": "shared"}, nil)
	raced := false
	r.tools.M = interleave{r.m, func() {
		if raced {
			return
		}
		raced = true
		r.tools.M = r.m // the private machine's own call goes straight through
		r.must("agent-priv", toolWrite, m{"name": "shared", "path": "/out", "content": "owner data"}, nil)
	}}
	var out struct{ Stdout string }
	err := r.call("agent", toolExec, m{"name": "shared", "argv": []string{"cat", "/out"}}, &out)
	if !raced {
		t.Fatal("the interleaving hook did not run")
	}
	if err == nil || !strings.Contains(err.Error(), "private") || strings.Contains(out.Stdout, "owner data") {
		t.Fatalf("public machine's command after a private write: %v, stdout %q", err, out.Stdout)
	}
	if w, _ := r.m.Get(workerID(pub.Lineage, "shared")); w.Label != vm.Private {
		t.Fatalf("worker is %v", w.Label)
	}
}

// record keeps the last command the tools handed the manager.
type record struct {
	*vm.Manager
	cmd     vm.Command
	timeout time.Duration
}

func (r *record) Exec(ctx context.Context, id string, c vm.Command, timeout time.Duration) (vm.ExecResult, error) {
	r.cmd, r.timeout = c, timeout
	return r.Manager.Exec(ctx, id, c, timeout)
}

// The bounds hold exactly where they say: timeouts clamp (overflow
// included), output is capped by default, paths follow "--", and argv
// limits sit at their values (M15, M16, M18, M20, M21, M23 on #146).
func TestCAP8CommandsAreBoundedExactly(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	rec := &record{Manager: r.m}
	r.tools.M = rec
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	for _, c := range []struct {
		args m
		want time.Duration
	}{
		{m{}, DefaultTimeout},
		{m{"timeout_seconds": 2}, 2 * time.Second},
		{m{"timeout_seconds": 3600}, MaxTimeout},
		{m{"timeout_seconds": 1e12}, MaxTimeout},
	} {
		c.args["name"], c.args["argv"] = "w", []string{"echo"}
		r.must("agent", toolExec, c.args, nil)
		if rec.timeout != c.want {
			t.Errorf("timeout %v ran with %v, want %v", c.args["timeout_seconds"], rec.timeout, c.want)
		}
		if rec.cmd.MaxOutput != MaxOutput {
			t.Errorf("exec output cap %d, want %d", rec.cmd.MaxOutput, MaxOutput)
		}
	}
	r.call("agent", toolRead, m{"name": "w", "path": "/-n"}, nil)
	if a := rec.cmd.Argv; len(a) != 5 || a[0] != "tail" || a[3] != "--" || a[4] != "/-n" {
		t.Errorf("read ran %q", a)
	}
	r.must("agent", toolWrite, m{"name": "w", "path": "/-a", "content": "x"}, nil)
	if a := rec.cmd.Argv; len(a) != 3 || a[0] != "tee" || a[1] != "--" || a[2] != "/-a" {
		t.Errorf("write ran %q", a)
	}

	argv := func(n, size int) []string {
		a := make([]string, n)
		for i := range a {
			a[i] = "x"
		}
		a[0] = strings.Repeat("x", size-(n-1))
		return a
	}
	r.must("agent", toolExec, m{"name": "w", "argv": argv(MaxArgs, MaxArgs)}, nil)
	r.must("agent", toolExec, m{"name": "w", "argv": argv(1, MaxArgBytes)}, nil)
	for _, c := range []struct {
		argv []string
		want string
	}{
		{argv(MaxArgs+1, MaxArgs+1), fmt.Sprintf("argv needs 1 to %d entries", MaxArgs)},
		{argv(1, MaxArgBytes+1), fmt.Sprintf("at most %d bytes", MaxArgBytes)},
	} {
		if err := r.call("agent", toolExec, m{"name": "w", "argv": c.argv}, nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("argv of %d entries: %v, want %q", len(c.argv), err, c.want)
		}
	}
}

// A fork stops at the per-lineage cap, counting the forks it would make
// (M12 on #146).
func TestCAP8ForkStopsAtTheWorkerCap(t *testing.T) {
	r := newRig(t, 16000)
	r.agent("agent", vm.Public)
	for i := range MaxWorkers - 1 {
		r.must("agent", toolCreate, m{"name": fmt.Sprintf("w%d", i), "mem_mb": MinMemMB}, nil)
	}
	err := r.call("agent", toolFork, m{"name": "w0", "into": []string{"f1", "f2"}}, nil)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("at most %d workers", MaxWorkers)) {
		t.Fatalf("fork past the cap: %v", err)
	}
	r.must("agent", toolFork, m{"name": "w0", "into": []string{"f1"}}, nil)
}

// A diff returns at most MaxChanges entries and says how many there were
// (M28 on #146).
func TestCAP8DiffIsCapped(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	var a, b struct{ Snapshot string }
	r.must("agent", toolCkpt, m{"name": "w"}, &a)
	for i := range MaxChanges + 1 {
		r.must("agent", toolWrite, m{"name": "w", "path": fmt.Sprintf("/f%d", i), "content": "x"}, nil)
	}
	r.must("agent", toolCkpt, m{"name": "w"}, &b)
	var d struct {
		Changes []struct{ Path string }
		Total   int
	}
	r.must("agent", toolDiff, m{"a": a.Snapshot, "b": b.Snapshot}, &d)
	if len(d.Changes) != MaxChanges || d.Total != MaxChanges+1 {
		t.Fatalf("diff = %d changes, total %d; want %d, %d", len(d.Changes), d.Total, MaxChanges, MaxChanges+1)
	}
}

// The tools trust a machine's own record, not the lineage they are told:
// a caller naming another lineage is refused (M4), and a worker whose short
// ID matches but whose record holds another lineage is not the caller's
// (M5 on #146).
func TestCAP8LineageComesFromTheMachinesRecord(t *testing.T) {
	r := newRig(t, 8000)
	a := r.agent("a", vm.Public)
	b := r.agent("b", vm.Public)
	r.must("b", toolCreate, m{"name": "w"}, nil)
	if _, _, err := r.tools.Call(context.Background(), "a", b.Lineage, toolList, nil); err == nil || err.Error() != "broker: unknown machine" {
		t.Fatalf("a caller naming another lineage: %v", err)
	}
	// As if b's lineage hashed like a's: a worker under a's ID, in b's lineage.
	if _, err := r.m.CreateWorker(context.Background(), workerID(a.Lineage, "x"), b.Lineage, vm.Spec{Image: "base", Class: admission.Experiment, MemMB: MinMemMB}); err != nil {
		t.Fatal(err)
	}
	if err := r.call("a", toolExec, m{"name": "x", "argv": []string{"echo"}}, nil); err == nil || err.Error() != errNoWorker.Error() {
		t.Fatalf("a reached a worker recorded in b's lineage: %v", err)
	}
}

// A fork or create waiting on a busy worker holds up no other call: not
// another lineage's tools, not the same lineage's other creates, and not
// Reap (L3 MUST-4 on #146).
func TestCAP8ABusyWorkerHoldsUpNoOtherCall(t *testing.T) {
	r := newRig(t, 16000)
	r.agent("a", vm.Public)
	r.agent("b", vm.Public)
	r.must("a", toolCreate, m{"name": "busy"}, nil)
	ran := make(chan error, 2)
	go func() {
		ran <- r.call("a", toolExec, m{"name": "busy", "argv": []string{"sleep"}, "timeout_seconds": 600}, nil)
	}()
	time.Sleep(20 * time.Millisecond) // the command holds the worker
	go func() { ran <- r.call("a", toolFork, m{"name": "busy", "into": []string{"copy"}}, nil) }()
	time.Sleep(20 * time.Millisecond) // the fork waits on the worker
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.must("b", toolCreate, m{"name": "w"}, nil)
		r.must("a", toolCreate, m{"name": "other"}, nil)
		r.tools.Reap(context.Background())
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("other calls waited behind a busy worker")
	}
	mc, _ := r.m.Get("a")
	if err := r.m.Destroy(context.Background(), workerID(mc.Lineage, "busy")); err != nil {
		t.Fatal(err)
	}
	<-ran
	<-ran
}

// Concurrent creates and forks cannot race past the cap: the slots are
// reserved before any machine is made (security R1, L3 MUST-4 on #146).
func TestCAP8ConcurrentCreatesStayUnderTheCap(t *testing.T) {
	r := newRig(t, 64000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "src", "mem_mb": MinMemMB}, nil)
	var wg sync.WaitGroup
	for i := range 2 * MaxWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				r.call("agent", toolCreate, m{"name": fmt.Sprintf("c%d", i), "mem_mb": MinMemMB}, nil)
			} else {
				r.call("agent", toolFork, m{"name": "src", "into": []string{fmt.Sprintf("f%d", i)}}, nil)
			}
		}()
	}
	wg.Wait()
	mc, _ := r.m.Get("agent")
	if n := len(r.m.Workers(mc.Lineage)); n != MaxWorkers {
		t.Fatalf("%d workers after the race, want exactly %d", n, MaxWorkers)
	}
}

// Potency R3 on #146: a file reads in pieces, and binary goes both ways
// as base64.
func TestCAP8FilesReadInPiecesAndBinaryRoundTrips(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	r.must("agent", toolWrite, m{"name": "w", "path": "/f", "content": "0123456789"}, nil)
	var part struct {
		Content   string
		Truncated bool
	}
	r.must("agent", toolRead, m{"name": "w", "path": "/f", "offset": 3, "length": 4}, &part)
	if part.Content != "3456" || !part.Truncated {
		t.Fatalf("read 4 at 3 = %+v", part)
	}
	r.must("agent", toolRead, m{"name": "w", "path": "/f", "offset": 8}, &part)
	if part.Content != "89" || part.Truncated {
		t.Fatalf("read the tail = %+v", part)
	}
	bin := []byte{0, 0xff, 0xfe, '\n', 7}
	enc := base64.StdEncoding.EncodeToString(bin)
	r.must("agent", toolWrite, m{"name": "w", "path": "/b", "content_base64": enc}, nil)
	r.must("agent", toolRead, m{"name": "w", "path": "/b", "base64": true}, &part)
	if part.Content != enc {
		t.Fatalf("binary read back = %q, want %q", part.Content, enc)
	}
	var ex execOut
	r.must("agent", toolExec, m{"name": "w", "argv": []string{"stdin"}, "stdin_base64": enc, "output_base64": true}, &ex)
	if ex.Stdout != enc {
		t.Fatalf("binary through exec = %q", ex.Stdout)
	}
	for _, bad := range []m{
		{"name": "w", "path": "/b", "content": "x", "content_base64": enc},
		{"name": "w", "path": "/b", "content_base64": "%%%"},
	} {
		if err := r.call("agent", toolWrite, bad, nil); err == nil {
			t.Errorf("write %v accepted", bad)
		}
	}
	if err := r.call("agent", toolRead, m{"name": "w", "path": "/f", "length": MaxOutput + 1}, nil); err == nil {
		t.Error("read longer than the cap accepted")
	}
}

// Security R2 on #146: while STOP holds, no worker command starts.
func TestCAP8StopHoldsWorkerCommands(t *testing.T) {
	r := newRig(t, 8000)
	stopped := false
	r.tools.Stopped = func() bool { return stopped }
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	stopped = true
	for _, c := range []struct {
		tool string
		args m
	}{
		{toolExec, m{"name": "w", "argv": []string{"echo"}}},
		{toolRead, m{"name": "w", "path": "/f"}},
		{toolWrite, m{"name": "w", "path": "/f", "content": "x"}},
	} {
		if err := r.call("agent", c.tool, c.args, nil); err == nil || !strings.Contains(err.Error(), "STOP") {
			t.Errorf("%s under STOP: %v", c.tool, err)
		}
	}
	stopped = false
	r.must("agent", toolExec, m{"name": "w", "argv": []string{"echo"}}, nil)
}

// hold blocks Fork until release is closed, so a reservation stays pending.
type hold struct {
	*vm.Manager
	forking chan struct{}
	release chan struct{}
}

func (h hold) Fork(ctx context.Context, id string, ids []string) (vm.Snapshot, error) {
	close(h.forking)
	<-h.release
	return h.Manager.Fork(ctx, id, ids)
}

// A fork's reserved slots count before its workers exist: a create that
// would pass the cap meanwhile is refused (L3 SHOULD on #146).
func TestCAP8PendingForkHoldsItsSlots(t *testing.T) {
	r := newRig(t, 16000)
	r.agent("agent", vm.Public)
	for i := range MaxWorkers - 1 {
		r.must("agent", toolCreate, m{"name": fmt.Sprintf("w%d", i), "mem_mb": MinMemMB}, nil)
	}
	h := hold{r.m, make(chan struct{}), make(chan struct{})}
	r.tools.M = h
	forked := make(chan error, 1)
	go func() { forked <- r.call("agent", toolFork, m{"name": "w0", "into": []string{"f"}}, nil) }()
	<-h.forking
	err := r.call("agent", toolCreate, m{"name": "late", "mem_mb": MinMemMB}, nil)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("at most %d workers", MaxWorkers)) {
		t.Fatalf("create beside a pending fork at the cap: %v", err)
	}
	close(h.release)
	if err := <-forked; err != nil {
		t.Fatal(err)
	}
	if err := r.call("agent", toolCreate, m{"name": "late", "mem_mb": MinMemMB}, nil); err == nil {
		t.Fatal("create past the cap after the fork")
	}
}
