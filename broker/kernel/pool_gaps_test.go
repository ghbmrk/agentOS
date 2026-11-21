package kernel_test

// REQ: RES-5

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// A pool entry whose body does not decode stops the replay as corrupt; it is
// never folded as an empty pool (RES-5, LOG-5).
func TestAPoolEntryThatDoesNotDecodeIsCorrupt(t *testing.T) {
	for _, typ := range []string{kernel.TPoolRead, kernel.TPoolReset, kernel.TReserveUp, kernel.TReserveDown} {
		s, err := kernel.Replay(nil, []kernel.Entry{{Seq: 1, At: 1, Type: typ, V: 2, Body: json.RawMessage(`"x"`)}})
		if !errors.Is(err, kernel.ErrCorrupt) || s != nil {
			t.Fatalf("%s with an undecodable body replayed: %v", typ, err)
		}
	}
}

// A reading written past the kernel whose use is not a share of the pool
// changes no window on replay; the rest of the reading still folds (RES-5,
// KRN-1).
func TestAReplayedReadingOutsideThePoolIsSkipped(t *testing.T) {
	body := `{"pool":"p","windows":[{"window":"a","used":-1,"reset_at":5},{"window":"b","used":1001,"reset_at":5},{"window":"c","used":1000,"reset_at":5}]}`
	s, err := kernel.Replay(nil, []kernel.Entry{{Seq: 1, At: 1, Type: kernel.TPoolRead, V: 2, Body: json.RawMessage(body)}})
	must(t, err)
	ws := s.Pools["p"].Windows
	if len(ws) != 1 || ws["c"] != (kernel.Window{Used: 1000, ResetAt: 5}) {
		t.Fatalf("replayed windows %+v, want only c", ws)
	}
}

// The lowerings in their hold list in pool order, whatever the map's order.
func TestPendingReservesListInPoolOrder(t *testing.T) {
	s := kernel.NewState(nil)
	names := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	for i, n := range names {
		s.Pools[n] = kernel.Pool{Reserve: 300, Lowering: &kernel.Lowering{To: int64(i), Live: 100}}
	}
	for range 20 {
		got := s.PendingReserves(0)
		var pools []string
		for _, p := range got {
			pools = append(pools, p.Pool)
		}
		if !slices.Equal(pools, names) {
			t.Fatalf("pending reserves in order %v, want %v", pools, names)
		}
	}
}

// Windows due together reset in window order, so two kernels that read the
// same figures log the same entries (RES-5, KRN-7).
func TestWindowsDueTogetherResetInWindowOrder(t *testing.T) {
	names := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	for range 5 {
		r := newRig(t)
		must(t, r.k.Reserve(1, "p", 100))
		var ws []kernel.WindowReading
		for _, n := range names {
			ws = append(ws, kernel.WindowReading{Window: n, Used: 950, ResetAt: 1_000})
		}
		must(t, r.k.ReadPool(2, "p", ws))
		if rf := r.k.AdmitPool(1_000, "p"); rf != nil {
			t.Fatalf("every window reset: %v", rf)
		}
		es := r.k.Log().Entries()
		var got []string
		for _, e := range es[len(es)-len(names):] {
			var b struct{ Window string }
			must(t, json.Unmarshal(e.Body, &b))
			if e.Type != kernel.TPoolReset {
				t.Fatalf("entry %s, want a reset", e.Type)
			}
			got = append(got, b.Window)
		}
		if !slices.Equal(got, names) {
			t.Fatalf("resets in order %v, want %v", got, names)
		}
	}
}
