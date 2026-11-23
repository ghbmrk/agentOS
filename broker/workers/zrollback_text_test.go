package workers

// REQ: CAP-8

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
)

// A worker destroyed and recreated under its name cannot restart from a
// snapshot of its earlier life, and the refusal says so, not that the
// snapshot is of another lineage; worker_diff still compares it, as the
// text promises (#1708, from #1575 UX U-L1).
func TestCAP8RollbackToAnEarlierLifeSaysSo(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	var old struct{ Snapshot string }
	r.must("agent", toolCkpt, m{"name": "w"}, &old)
	r.must("agent", toolDestroy, m{"name": "w"}, nil)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	err := r.call("agent", toolRollback, m{"name": "w", "snapshot": old.Snapshot}, nil)
	if want := "worker w: that snapshot is of an earlier worker of this name, destroyed since; a new worker cannot restart from it, though worker_diff can still compare it"; err == nil || err.Error() != want {
		t.Fatalf("rollback to an earlier life: %v", err)
	}
	var now struct{ Snapshot string }
	r.must("agent", toolCkpt, m{"name": "w"}, &now)
	r.must("agent", toolDiff, m{"a": old.Snapshot, "b": now.Snapshot}, nil)
}

// A snapshot of a sibling worker is not this worker's either; the text
// names what a worker can restart from instead of a lineage or a name.
func TestCAP8RollbackToAnotherWorkersSnapshotSaysWhatItCanUse(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "a"}, nil)
	r.must("agent", toolCreate, m{"name": "b"}, nil)
	var sb struct{ Snapshot string }
	r.must("agent", toolCkpt, m{"name": "b"}, &sb)
	err := r.call("agent", toolRollback, m{"name": "a", "snapshot": sb.Snapshot}, nil)
	if want := "worker a: that snapshot is of another worker; a worker restarts only from its own snapshots or the one it was forked from"; err == nil || err.Error() != want {
		t.Fatalf("rollback to a sibling's snapshot: %v", err)
	}
}

// worker_destroy's description no longer suggests the snapshots stay
// usable for a worker recreated under the name.
func TestCAP8DestroyDescriptionSaysARecreateCannotRestart(t *testing.T) {
	for _, tl := range (&Tools{}).List() {
		if tl["name"] == toolDestroy {
			d, _ := tl["description"].(string)
			if want := "Stop a worker and free its memory. Its snapshots stay in the broker's custody, but a worker created again under this name cannot restart from them."; d != want {
				t.Fatalf("destroy description = %q", d)
			}
			return
		}
	}
	t.Fatal("no destroy tool")
}
