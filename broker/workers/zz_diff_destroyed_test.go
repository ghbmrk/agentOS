package workers

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: PLN-6
// Two snapshots of a destroyed worker, with no worker of its name made
// again, still compare in either order: the caller owns both, so the
// answer cannot hang on which one is named first (#6618, from #6602 UX).
func TestCAP8DiffComparesADestroyedWorkersSnapshotsInEitherOrder(t *testing.T) {
	r := newRig(t, 8000)
	r.agent("agent", vm.Public)
	r.must("agent", toolCreate, m{"name": "w"}, nil)
	r.must("agent", toolCreate, m{"name": "live"}, nil)
	var a, b, l struct{ Snapshot string }
	r.must("agent", toolCkpt, m{"name": "w"}, &a)
	r.must("agent", toolCkpt, m{"name": "w"}, &b)
	r.must("agent", toolCkpt, m{"name": "live"}, &l)
	r.must("agent", toolDestroy, m{"name": "w"}, nil)
	for _, p := range [][2]string{{a.Snapshot, b.Snapshot}, {b.Snapshot, a.Snapshot}, {a.Snapshot, l.Snapshot}, {l.Snapshot, a.Snapshot}} {
		var d struct{ Total int }
		r.must("agent", toolDiff, m{"a": p[0], "b": p[1]}, &d)
	}
}
