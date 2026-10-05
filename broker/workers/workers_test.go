package workers

// REQ: CAP-8, REV-5, A14, A15

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// runtime stands in for gVisor: a guest's files are its upper layer, its
// memory a checkpointed marker. Exec understands cat, tee, echo and false.
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
func (r *runtime) Exec(_ context.Context, id string, c vm.Command) (vm.ExecResult, error) {
	r.mu.Lock()
	l, ok := r.running[id]
	r.mu.Unlock()
	if !ok {
		return vm.ExecResult{}, fmt.Errorf("%s not running", id)
	}
	a := c.Argv
	path := func() string { return filepath.Join(l.Upper, strings.TrimPrefix(a[len(a)-1], "/")) }
	switch a[0] {
	case "echo":
		return vm.ExecResult{Stdout: []byte(strings.Join(a[1:], " "))}, nil
	case "cat":
		b, err := os.ReadFile(path())
		if err != nil {
			return vm.ExecResult{ExitCode: 1, Stderr: []byte("cat: no such file")}, nil
		}
		return vm.ExecResult{Stdout: b}, nil
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
