package workers

// REQ: CAP-8, CAP-1

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

// Tests that pin the exact answer, state or bound of lines the rollback
// text change (#1708) puts under mutation: each fails when its line is
// changed or its statement deleted (MUT-gate, #4908).

const nameMsg = "name: lowercase letters, digits and '-', at most 20"

func mustFail(t *testing.T, r *rig, tool string, args any, want string) {
	t.Helper()
	err := r.call("agent", tool, args, nil)
	if err == nil || err.Error() != want {
		t.Fatalf("%s %v: error %v, want %q", tool, args, err, want)
	}
}

func fitJSON(t *testing.T, r *rig, mem int64) fitOut {
	t.Helper()
	var f fitOut
	r.must("agent", toolFit, m{"mem_mb": mem}, &f)
	return f
}

// A call in flight leaves nothing in the count once it returns.
func TestCAP8ACallLeavesNoCountBehind(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolList, m{}, nil)
	r.tools.mu.Lock()
	n := len(r.tools.calls)
	r.tools.mu.Unlock()
	if n != 0 || r.tools.Busy("agent") {
		t.Fatalf("after a returned call: %d counts, busy %v", n, r.tools.Busy("agent"))
	}
}

// A worker cannot drive workers, even through its own caller identity.
func TestCAP8AWorkerCannotDriveWorkers(t *testing.T) {
	r := newRig(t, 8000)
	ag := r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	_, handled, err := r.tools.Call(context.Background(), workerID(ag.Lineage, "w"), ag.Lineage, toolList, nil)
	if !handled || err == nil || err.Error() != "a worker cannot drive workers" {
		t.Fatalf("worker calling a tool: handled %v, %v", handled, err)
	}
}

// No arguments at all read as an empty object.
func TestCAP8NoArgumentsReadAsAnEmptyObject(t *testing.T) {
	r := newRig(t, 8000)
	ag := r.agent("agent", vm.Public)
	_, _, err := r.tools.Call(context.Background(), "agent", ag.Lineage, toolCkpt, nil)
	if err == nil || err.Error() != nameMsg {
		t.Fatalf("checkpoint with no arguments: %v", err)
	}
}

// Names are checked before any lookup, and a provider-prefixed name is
// never a worker the tools reach, even if a machine of that ID exists.
func TestCAP8NamesAreCheckedBeforeLookup(t *testing.T) {
	r := newRig(t, 8000)
	ag := r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "src"}, nil)
	pn := vm.ProviderPrefix + "x"
	spec := vm.Spec{Image: "base", Class: admission.Experiment, MemMB: 256, Label: vm.Public, Argv: []string{"idle"}}
	if _, err := r.m.CreateWorker(context.Background(), workerID(ag.Lineage, pn), ag.Lineage, spec); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{toolCkpt, toolDestroy, toolKeep, toolFork, toolRollback} {
		args := m{"name": "BAD", "into": []string{"a"}, "snapshot": "s"}
		mustFail(t, r, tool, args, nameMsg)
	}
	for _, tool := range []string{toolCkpt, toolDestroy, toolKeep} {
		mustFail(t, r, tool, m{"name": pn}, "no such worker")
	}
	mustFail(t, r, toolDestroy, m{"name": "nope"}, "no such worker")
	mustFail(t, r, toolKeep, m{"name": "nope"}, "no such worker")
	mustFail(t, r, toolCreate, m{"name": "BAD"}, nameMsg)
	mustFail(t, r, toolFork, m{"name": "src", "into": []string{"a", "BAD"}}, `into: bad name "BAD"`)
	mustFail(t, r, toolFork, m{"name": "src", "into": []string{"a", pn}}, errProviderName.s)
	var l struct{ Workers []struct{ Name string } }
	r.must("agent", toolList, m{}, &l)
	if len(l.Workers) != 2 {
		t.Fatalf("a refused name made or removed a worker: %+v", l)
	}
}

// A name already in use is the worker cap's refusal, not a start's.
func TestCAP8ReservingAHeldNameIsRefused(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	want := fmt.Sprintf("at most %d workers at once, each with its own name; destroy one first", MaxWorkers)
	mustFail(t, r, toolCreate, m{"name": "w"}, want)
	r.must("agent", toolCreate, m{"name": "s"}, nil)
	mustFail(t, r, toolFork, m{"name": "s", "into": []string{"w"}},
		fmt.Sprintf("into needs 1 or more new names, with at most %d workers at once", MaxWorkers))
}

// mem_mb may be the least and the most a worker may have.
func TestCAP8MemoryBoundsAreInclusive(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "lo", "mem_mb": MinMemMB}, nil)
	r.must("agent", toolCreate, m{"name": "hi", "mem_mb": r.tools.MaxMemMB}, nil)
	if f := fitJSON(t, r, MinMemMB); f.MemMB != MinMemMB {
		t.Fatalf("fit at the least: %+v", f)
	}
	if f := fitJSON(t, r, r.tools.MaxMemMB); f.MemMB != r.tools.MaxMemMB {
		t.Fatalf("fit at the most: %+v", f)
	}
	mustFail(t, r, toolFit, m{"mem_mb": MinMemMB - 1}, "mem_mb must be between 64 and 2048")
}

// Exec's stdin, and read and write's paths, are checked and answered
// exactly.
func TestCAP8InputsAreCheckedAndAnsweredExactly(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	mustFail(t, r, toolExec, m{"name": "w", "argv": []string{"echo"}, "stdin_base64": "!!"}, "base64 input does not decode")
	r.must("agent", toolExec, m{"name": "w", "argv": []string{"echo"}, "stdin": strings.Repeat("x", MaxStdin)}, nil)
	for _, tool := range []string{toolRead, toolWrite} {
		for _, p := range []string{"f", "/a\x00b", "/" + strings.Repeat("a", 4096)} {
			mustFail(t, r, tool, m{"name": "w", "path": p}, "path must be absolute")
		}
	}
	err := r.call("agent", toolRead, m{"name": "w", "path": "/" + strings.Repeat("a", 4095)}, nil)
	if err == nil || strings.Contains(err.Error(), "absolute") {
		t.Fatalf("a path of 4096 bytes is a path: %v", err)
	}
	mustFail(t, r, toolRead, m{"name": "w", "path": "/nope"}, "cannot read /nope: no such file")
}

// teeFails is a runtime whose tee exits non-zero.
type teeFails struct{ *runtime }

func (r teeFails) Exec(ctx context.Context, id string, c vm.Command) (vm.ExecResult, error) {
	if c.Argv[0] == "tee" {
		return vm.ExecResult{ExitCode: 1, Stderr: []byte("read-only")}, nil
	}
	return r.runtime.Exec(ctx, id, c)
}

func TestCAP8WriteSaysWhyItFailed(t *testing.T) {
	r := newRigOn(t, 8000, 0, teeFails{&runtime{running: map[string]vm.Launch{}}})
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	mustFail(t, r, toolWrite, m{"name": "w", "path": "/f", "content": "x"}, "cannot write /f: read-only")
}

// A snapshot that is not one's own is refused as such, whichever side of
// a diff or rollback it is on.
func TestCAP8SnapshotsNotOwnedAreRefused(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	var s struct{ Snapshot string }
	r.must("agent", toolCkpt, m{"name": "w"}, &s)
	bad := `no snapshot "zz" of your workers`
	mustFail(t, r, toolDiff, m{"a": "zz", "b": s.Snapshot}, bad)
	mustFail(t, r, toolDiff, m{"a": s.Snapshot, "b": "zz"}, bad)
	mustFail(t, r, toolRollback, m{"name": "w", "snapshot": "zz"}, bad)
}

// A refusal for want of room says what to do, in the tool's own words.
func TestCAP8NoRoomIsAnsweredInTheToolsWords(t *testing.T) {
	r := newRig(t, 1000)
	r.agent("agent", vm.Public)
	want := "no room for worker big now: destroy a worker, or ask for less memory with mem_mb"
	mustFail(t, r, toolCreate, m{"name": "big", "mem_mb": 1024}, want)
}

// What the tools remember of use: set when a worker is made, named,
// kept or deleted from, and dropped when it goes, but not for a start
// that failed.
func TestCAP8UseIsRecordedOnlyForWhatExists(t *testing.T) {
	r := newRig(t, 1000)
	clk := newClock(r)
	ag := r.agent("agent", vm.Public)
	t0 := clk.t
	r.must("agent", toolCreate, m{"name": "src", "mem_mb": MinMemMB}, nil)
	used := func(name string) (time.Time, bool) {
		r.tools.mu.Lock()
		defer r.tools.mu.Unlock()
		v, ok := r.tools.used[workerID(ag.Lineage, name)]
		return v, ok
	}
	if v, ok := used("src"); !ok || !v.Equal(t0) {
		t.Fatalf("a made worker's use = %v, %v", v, ok)
	}
	// A start that fails records nothing.
	mustFail(t, r, toolCreate, m{"name": "big", "mem_mb": 2000}, "no room for worker big now: destroy a worker, or ask for less memory with mem_mb")
	if _, ok := used("big"); ok {
		t.Fatal("a refused create left a use record")
	}
	mustFail(t, r, toolFork, m{"name": "src", "into": []string{"f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8"}},
		"no room for worker src now: destroy a worker, or ask for less memory with mem_mb")
	if _, ok := used("f1"); ok {
		t.Fatal("a refused fork left a use record")
	}
	clk.t = t0.Add(time.Minute)
	r.must("agent", toolFork, m{"name": "src", "into": []string{"a", "b", "c"}}, nil)
	for _, n := range []string{"a", "b", "c"} {
		if v, ok := used(n); !ok || !v.Equal(clk.t) {
			t.Fatalf("a forked worker %s's use = %v, %v", n, v, ok)
		}
	}
	// keep names the winner and drops its siblings.
	clk.t = t0.Add(2 * time.Minute)
	r.must("agent", toolKeep, m{"name": "a"}, nil)
	if v, _ := used("a"); !v.Equal(clk.t) {
		t.Fatalf("keep did not record the winner's use: %v", v)
	}
	for _, n := range []string{"b", "c"} {
		if _, ok := used(n); ok {
			t.Fatalf("keep left a use record for the discarded %s", n)
		}
	}
	// delete names its worker.
	clk.t = t0.Add(3 * time.Minute)
	r.must("agent", toolDelete, m{"name": "src", "paths": []string{"/x"}}, nil)
	if v, _ := used("src"); !v.Equal(clk.t) {
		t.Fatalf("delete did not record the worker's use: %v", v)
	}
	r.must("agent", toolDestroy, m{"name": "src"}, nil)
	if _, ok := used("src"); ok {
		t.Fatal("destroy left a use record")
	}
}

// touch and Reap start from no records at all.
func TestCAP8UseRecordsStartEmpty(t *testing.T) {
	tl := &Tools{}
	tl.touch("x")
	if _, ok := tl.used["x"]; !ok {
		t.Fatal("touch on a new Tools recorded nothing")
	}
	r := newRig(t, 8000)
	now := time.Now()
	r.tools.Now = func() time.Time { return now }
	ag := r.agent("agent", vm.Public)
	spec := vm.Spec{Image: "base", Class: admission.Experiment, MemMB: 256, Label: vm.Public, Argv: []string{"idle"}}
	if _, err := r.m.CreateWorker(context.Background(), workerID(ag.Lineage, "d"), ag.Lineage, spec); err != nil {
		t.Fatal(err)
	}
	// First seen after a restart: the hour starts now.
	if p := r.tools.Reap(context.Background()); len(p) != 0 {
		t.Fatalf("a worker first seen was parked: %v", p)
	}
	now = now.Add(IdleAfter)
	if p := r.tools.Reap(context.Background()); len(p) != 1 {
		t.Fatalf("a worker idle for the whole hour was not parked: %v", p)
	}
}

// A worker made and never named again parks at exactly IdleAfter.
func TestCAP8AMadeWorkerParksAtExactlyIdleAfter(t *testing.T) {
	r := newRig(t, 8000)
	now := time.Now()
	r.tools.Now = func() time.Time { return now }
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	now = now.Add(IdleAfter - time.Nanosecond)
	if p := r.tools.Reap(context.Background()); len(p) != 0 {
		t.Fatalf("parked early: %v", p)
	}
	now = now.Add(time.Nanosecond)
	if p := r.tools.Reap(context.Background()); len(p) != 1 {
		t.Fatalf("not parked at IdleAfter: %v", p)
	}
}

// A worker of another lineage under this one's prefix is not listed.
func TestCAP8ListSkipsAWorkerOfAnotherLineage(t *testing.T) {
	r := newRig(t, 8000)
	ag := r.agent("agent", vm.Public)
	spec := vm.Spec{Image: "base", Class: admission.Experiment, MemMB: 256, Label: vm.Public, Argv: []string{"idle"}}
	other := r.agent("other", vm.Public)
	if _, err := r.m.CreateWorker(context.Background(), workerID(ag.Lineage, "x"), other.Lineage, spec); err != nil {
		t.Fatal(err)
	}
	var l struct{ Workers []struct{ Name string } }
	r.must("agent", toolList, m{}, &l)
	if len(l.Workers) != 0 {
		t.Fatalf("listed %+v", l)
	}
}

// keep answers a vanished worker's siblings as no such worker, and a
// failure on the first sibling says nothing of what was destroyed.
func TestCAP8KeepAnswersExactly(t *testing.T) {
	r := newRig(t, 16000)
	ag := r.agent("agent", vm.Public)
	r.tools.M = making{r.m, workerID(ag.Lineage, "ghost")}
	mustFail(t, r, toolKeep, m{"name": "ghost"}, "no such worker")
	r.tools.M = r.m
	r.must("agent", toolCreate, m{"name": "src", "mem_mb": MinMemMB}, nil)
	r.must("agent", toolFork, m{"name": "src", "into": []string{"a", "b", "c"}}, nil)
	r.tools.M = failDestroy{r.m, workerID(ag.Lineage, "b")}
	err := r.call("agent", toolKeep, m{"name": "a"}, nil)
	if err == nil || !regexp.MustCompile(`^worker b: failed \(ref [0-9a-f]{8}\); the broker's log has the detail$`).MatchString(err.Error()) {
		t.Fatalf("keep failing on its first sibling: %v", err)
	}
}

// worker_delete's bounds and STOP answer exactly.
func TestCAP8DeleteChecksItsArguments(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	want := fmt.Sprintf("paths: 1 to %d absolute paths", vm.MaxDeletePaths)
	mustFail(t, r, toolDelete, m{"name": "w", "paths": []string{}}, want)
	many := make([]string, vm.MaxDeletePaths+1)
	for i := range many {
		many[i] = fmt.Sprint("/f", i)
	}
	mustFail(t, r, toolDelete, m{"name": "w", "paths": many}, want)
	r.must("agent", toolDelete, m{"name": "w", "paths": many[:vm.MaxDeletePaths]}, nil)
	stopped := true
	r.tools.Stopped = func() bool { return stopped }
	mustFail(t, r, toolDelete, m{"name": "w", "paths": []string{"/x"}}, errStopped.s)
	// STOP is answered before the worker is looked up.
	mustFail(t, r, toolDelete, m{"name": "nope", "paths": []string{"/x"}}, errStopped.s)
	// STOP landing after the first check, at the manager's own.
	calls := 0
	r.tools.Stopped = func() bool { calls++; return calls > 1 }
	mustFail(t, r, toolDelete, m{"name": "w", "paths": []string{"/x"}}, errStopped.s)
}

// fit's room: the declared and measured figures meet exactly, and the
// cache holds each lineage's figure.
func TestCAP1RoomIsTheSmallerAndCachedPerLineage(t *testing.T) {
	r := newRig(t, 8000)
	clk := newClock(r)
	r.agent("agent", vm.Public)
	r.tools.Free = func(admission.Class) int64 { return 0 }
	r.tools.Avail = func() (int64, error) { return 1024, nil }
	if f := fitJSON(t, r, MinMemMB); f.Fit != 0 {
		t.Fatalf("declared room 0 with 1024 measured fit %d", f.Fit)
	}
	clk.next()
	// Nothing declared, measured and equal: the same figure.
	r.tools.Free = func(admission.Class) int64 { return 1024 }
	if f := fitJSON(t, r, 512); f.Fit != 2 {
		t.Fatalf("1024 declared and measured fit %d of 512", f.Fit)
	}

	calls := 0
	tl := &Tools{Now: func() time.Time { return clk.t }, Free: func(admission.Class) int64 { calls++; return 1024 }}
	room := func(l string) { tl.room(caller{lineage: l}, admission.Experiment) }
	room("a")
	room("b")
	room("a")
	if calls != 2 {
		t.Fatalf("two lineages' rooms measured %d times, want 2", calls)
	}
	calls = 0
	tl = &Tools{Now: tl.Now, Free: func(admission.Class) int64 { calls++; return 1024 }}
	for i := range 4 * MaxWorkers {
		room(fmt.Sprint("l", i))
	}
	room("one-more")
	calls = 0
	room("l0")
	if calls != 0 {
		t.Fatalf("a full cache dropped its figures one entry early")
	}
}

// worker_fit's reason reads from the case it is in.
func TestCAP1FitSaysWhyOnlyWhenNothingFits(t *testing.T) {
	r := newRig(t, 8000)
	clk := newClock(r)
	ag := r.agent("agent", vm.Public)
	if f := fitJSON(t, r, DefaultMemMB); f.Fit != MaxWorkers || f.Why != "" {
		t.Fatalf("room to spare: %+v", f)
	}
	r.tools.Free = func(admission.Class) int64 { return 0 }
	clk.next()
	f := fitJSON(t, r, DefaultMemMB)
	if f.Fit != 0 || f.Why != "not enough free memory for one 256 MB worker now; work sequentially in one worker, ask for less memory, or destroy a worker" {
		t.Fatalf("no memory: %+v", f)
	}
	r.tools.Free = nil
	clk.next()
	r.tools.pending = map[string]string{}
	for i := range MaxWorkers {
		r.tools.pending[workerID(ag.Lineage, fmt.Sprint("p", i))] = ag.Lineage
	}
	f = fitJSON(t, r, DefaultMemMB)
	if f.Fit != 0 || f.Why != "you hold 16 workers, the most at once; destroy one first" {
		t.Fatalf("at the cap: %+v", f)
	}
}

// up_to_fit with nothing to fork into is the names' refusal, whatever
// the room.
func TestCAP1ForkUpToFitWithNoNamesAsksForNames(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "src"}, nil)
	r.tools.Free = func(admission.Class) int64 { return 0 }
	mustFail(t, r, toolFork, m{"name": "src", "into": []string{}, "up_to_fit": true},
		fmt.Sprintf("into needs 1 or more new names, with at most %d workers at once", MaxWorkers))
}
