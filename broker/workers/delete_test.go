package workers

// REQ: CAP-8, RES-4, REV-5, OP-6

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
)

type delOut struct {
	Results []struct {
		Path, Result string
	}
	Removed     int
	FreedBytes  int64 `json:"freed_bytes"`
	OverCap     bool  `json:"over_cap"`
	MoreRemains bool  `json:"more_remains"`
	State       string
}

// fullWorker is a running worker over its 1 MiB layer cap.
func fullWorker(t *testing.T) *rig {
	r := newRigLayer(t, 8000, 1<<20)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	r.must("agent", toolWrite, m{"name": "w", "path": "/small", "content": "x"}, nil)
	big := strings.Repeat("x", MaxStdin)
	for i := range 2 { // the second starts under the cap and ends over it
		r.must("agent", toolWrite, m{"name": "w", "path": fmt.Sprintf("/big%d", i), "content": big}, nil)
	}
	return r
}

// Over its cap a worker takes only worker_delete; deleting enough starts
// it again and commands run, and not enough leaves it stopped and
// refusing (security R-DEL1, R-DEL6, R-DEL7 on CAP-8c).
func TestCAP8cDeleteShrinksAFullWorkerInPlace(t *testing.T) {
	r := fullWorker(t)
	if err := r.call("agent", toolExec, m{"name": "w", "argv": []string{"echo"}}, nil); err == nil || !strings.Contains(err.Error(), "worker_delete") {
		t.Fatalf("exec over the cap: %v", err)
	}
	var d delOut
	r.must("agent", toolDelete, m{"name": "w", "paths": []string{"/small", "/nope"}}, &d)
	if !d.OverCap || d.State != "stopped" || d.Removed != 1 || d.Results[0].Result != "removed" || d.Results[1].Result != "not_found" {
		t.Fatalf("not enough deleted = %+v", d)
	}
	if err := r.call("agent", toolExec, m{"name": "w", "argv": []string{"echo"}}, nil); err == nil {
		t.Fatal("exec ran on a worker still over its cap")
	}
	r.must("agent", toolDelete, m{"name": "w", "paths": []string{"/big1"}}, &d)
	if d.OverCap || d.State != "running" || d.FreedBytes < MaxStdin {
		t.Fatalf("enough deleted = %+v", d)
	}
	var ex execOut
	r.must("agent", toolExec, m{"name": "w", "argv": []string{"cat", "/big0"}}, &ex)
	if !strings.HasPrefix(ex.Stdout, "xxx") {
		t.Fatalf("the worker lost what it kept: %q", ex.Stdout[:min(len(ex.Stdout), 10)])
	}
	// Under its cap a running worker starts again at once.
	r.must("agent", toolDelete, m{"name": "w", "paths": []string{"/big0"}}, &d)
	if d.State != "running" || d.OverCap {
		t.Fatalf("delete under the cap = %+v", d)
	}
}

// The answer names only the paths asked, with fixed codes and counts
// (R-DEL5), and the path cap holds (R-DEL7).
func TestCAP8cDeleteAnswersCodesAndCountsOnly(t *testing.T) {
	r := fullWorker(t)
	var raw map[string]any
	r.must("agent", toolDelete, m{"name": "w", "paths": []string{"/small"}}, &raw)
	for k := range raw {
		switch k {
		case "results", "removed", "freed_bytes", "over_cap", "more_remains", "state":
		default:
			t.Errorf("worker_delete answers %q", k)
		}
	}
	paths := make([]string, vm.MaxDeletePaths+1)
	for i := range paths {
		paths[i] = fmt.Sprintf("/f%d", i)
	}
	if err := r.call("agent", toolDelete, m{"name": "w", "paths": paths}, nil); err == nil {
		t.Fatalf("%d paths accepted", len(paths))
	}
	if err := r.call("agent", toolDelete, m{"name": "w", "paths": []string{}}, nil); err == nil {
		t.Fatal("no paths accepted")
	}
	r.must("agent", toolDelete, m{"name": "w", "paths": paths[:vm.MaxDeletePaths]}, nil)
}

// A public caller cannot delete in a private worker, and STOP holds
// deletions (R-DEL4, R-DEL7).
func TestCAP8cDeleteKeepsTheLabelRuleAndSTOP(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("priv", vm.Private)
	r.must("priv", toolCreate, m{"name": "w"}, nil)
	r.must("priv", toolWrite, m{"name": "w", "path": "/f", "content": "x"}, nil)
	// Another machine of the same lineage, public, sees the worker.
	pm, _ := r.m.Get("priv")
	pub := caller{machine: "priv", lineage: pm.Lineage, label: vm.Public, spec: pm.Spec}
	if _, err := r.tools.del(t.Context(), pub, []byte(`{"name":"w","paths":["/f"]}`)); err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("public delete in a private worker: %v", err)
	}
	stopped := true
	r.tools.Stopped = func() bool { return stopped }
	if err := r.call("priv", toolDelete, m{"name": "w", "paths": []string{"/f"}}, nil); err == nil || !strings.Contains(err.Error(), "STOP") {
		t.Fatalf("delete under STOP: %v", err)
	}
	stopped = false
	var d delOut
	r.must("priv", toolDelete, m{"name": "w", "paths": []string{"/f"}}, &d)
	if d.Results[0].Result != "removed" {
		t.Fatalf("delete after RESUME = %+v", d)
	}
}

// While STOP holds no worker starts: create, fork and rollback are
// refused (security R1 on #150).
func TestCAP8cSTOPRefusesStartingWorkers(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w", "mem_mb": MinMemMB}, nil)
	var snap struct{ Snapshot string }
	r.must("agent", toolCkpt, m{"name": "w"}, &snap)
	stopped := true
	r.tools.Stopped = func() bool { return stopped }
	for _, c := range []struct {
		tool string
		args m
	}{
		{toolCreate, m{"name": "x", "mem_mb": MinMemMB}},
		{toolFork, m{"name": "w", "into": []string{"f"}}},
		{toolRollback, m{"name": "w", "snapshot": snap.Snapshot}},
	} {
		if err := r.call("agent", c.tool, c.args, nil); err == nil || !strings.Contains(err.Error(), "no worker starts until RESUME") {
			t.Errorf("%s under STOP: %v", c.tool, err)
		}
	}
	r.must("agent", toolList, m{}, nil) // reads still work
	stopped = false
	r.must("agent", toolFork, m{"name": "w", "into": []string{"f"}}, nil)
}

// failDelete fails every deletion with a cause naming a host path.
type failDelete struct{ *vm.Manager }

func (failDelete) DeleteFiles(context.Context, string, vm.Deletion) (vm.DeleteReport, error) {
	return vm.DeleteReport{}, &os.PathError{Op: "openat", Path: "/var/lib/agentos/machines/x/upper", Err: syscall.EIO}
}

// A broker failure answers delete_failed alone: no host path or errno
// reaches the agent (L3 S1 on #166).
func TestCAP8cDeleteFailureNamesNoHostPath(t *testing.T) {
	r := fullWorker(t)
	r.tools.M = failDelete{r.m}
	err := r.call("agent", toolDelete, m{"name": "w", "paths": []string{"/small"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "delete_failed") || strings.Contains(err.Error(), "/") || strings.Contains(err.Error(), "input/output") {
		t.Fatalf("broker failure = %v", err)
	}
}
