package workers

// REQ: CAP-8

import (
	"strings"
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
	if err == nil || !strings.Contains(err.Error(), "an earlier worker of this name") || !strings.Contains(err.Error(), "worker_diff") {
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
	if err == nil || !strings.Contains(err.Error(), "of another worker") || strings.Contains(err.Error(), "lineage") || strings.Contains(err.Error(), "of this name") {
		t.Fatalf("rollback to a sibling's snapshot: %v", err)
	}
}

// worker_destroy's description no longer suggests the snapshots stay
// usable for a worker recreated under the name.
func TestCAP8DestroyDescriptionSaysARecreateCannotRestart(t *testing.T) {
	for _, tl := range (&Tools{}).List() {
		if tl["name"] == toolDestroy {
			d, _ := tl["description"].(string)
			if !strings.Contains(d, "cannot restart from them") || !strings.Contains(d, "worker_diff") {
				t.Fatalf("destroy description = %q", d)
			}
			return
		}
	}
	t.Fatal("no destroy tool")
}
