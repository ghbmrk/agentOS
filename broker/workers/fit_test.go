package workers

// REQ: CAP-1, A15, RES-2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm"
)

type fitOut struct {
	Fit         int    `json:"fit"`
	MemMB       int64  `json:"mem_mb"`
	FreeMB      int64  `json:"free_mb"`
	WorkersLeft int    `json:"workers_left"`
	Why         string `json:"why"`
}

// N is the smaller of what admission's declared budget and measured free
// memory hold, and what the lineage's worker cap leaves (CAP-1).
func TestCAP1FitIsTheSmallerOfDeclaredAndMeasured(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	declared, measured := int64(3000), int64(1000)
	var measureErr error
	r.tools.Free = func(admission.Class) int64 { return declared }
	r.tools.Avail = func() (int64, error) { return measured, measureErr }
	var f fitOut
	r.must("agent", toolFit, m{}, &f)
	if f.Fit != 3 || f.MemMB != DefaultMemMB || f.FreeMB != 1000 || f.WorkersLeft != MaxWorkers {
		t.Fatalf("fit = %+v, want 3 of %d MiB from 1000 measured", f, DefaultMemMB)
	}
	measured = 1 << 20
	r.must("agent", toolFit, m{"mem_mb": 500}, &f)
	if f.Fit != 6 || f.FreeMB != 3000 {
		t.Fatalf("fit at 500 MiB = %+v, want 6 from 3000 declared", f)
	}
	declared = 1 << 20
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	r.must("agent", toolFit, m{"mem_mb": MinMemMB}, &f)
	if f.Fit != MaxWorkers-1 || f.WorkersLeft != MaxWorkers-1 {
		t.Fatalf("fit beside one worker = %+v, want the cap's %d", f, MaxWorkers-1)
	}
	// Unreadable measurement: admission's budget alone, and it says so.
	declared, measureErr = 600, errors.New("no meminfo")
	r.must("agent", toolFit, m{}, &f)
	if f.Fit != 2 || !strings.Contains(f.Why, "declared") {
		t.Fatalf("fit without a measurement = %+v", f)
	}
	// At the floor N may be 0, and the answer says what to do.
	declared, measureErr = 100, nil
	r.must("agent", toolFit, m{}, &f)
	if f.Fit != 0 || !strings.Contains(f.Why, "sequential") {
		t.Fatalf("fit with no room = %+v", f)
	}
	if err := r.call("agent", toolFit, m{"mem_mb": 1}, nil); err == nil {
		t.Fatal("fit below the minimum worker size accepted")
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
	r.must("agent", toolCreate, m{"name": "src"}, nil)
	r.tools.Avail = func() (int64, error) { return 3 * DefaultMemMB, nil }
	var out struct {
		Workers []string
		Skipped []string
	}
	r.must("agent", toolFork, m{"name": "src", "into": []string{"a", "b", "c", "d", "e"}, "up_to_fit": true}, &out)
	if fmt.Sprint(out.Workers) != "[a b c]" || fmt.Sprint(out.Skipped) != "[d e]" {
		t.Fatalf("fork up to fit = %+v", out)
	}
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

// A15's shape within RES-2: on the floor's pool beside the agent, one
// guest asks how many fit, forks 8, tests each, and keeps the winner;
// admission never goes over its budget.
func TestA15EightWorkersWithinRES2(t *testing.T) {
	r := newRig(t, 4500) // budget.BaseCapMB, the floor's pool
	if _, err := r.m.Create(context.Background(), "agent", vm.Spec{Image: "base", Class: admission.Foreground, MemMB: 1600}); err != nil {
		t.Fatal(err)
	}
	r.tools.Free = func(admission.Class) int64 { return r.adm.Snapshot().FreeMB }
	r.must("agent", toolCreate, m{"name": "src"}, nil)
	r.must("agent", toolWrite, m{"name": "src", "path": "/task", "content": "solve"}, nil)
	var f fitOut
	r.must("agent", toolFit, m{}, &f)
	if f.Fit < 8 {
		t.Fatalf("only %d workers fit on the floor's pool, A15 needs 8", f.Fit)
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
