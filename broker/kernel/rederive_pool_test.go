package kernel_test

// REQ: RES-5, LOG-7

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// A pool window's reset is a decision the log's replay derives again: the
// window read closed, then its reset time passed, so Rederive reproduces
// the reset the kernel logged and counts it checked, not recorded.
func TestPoolResetRederives(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 100))
	must(t, r.k.ReadPool(2, "p", []kernel.WindowReading{{Window: "5h", Used: 950, ResetAt: 1_000}}))
	r.k.AdmitPool(1_000, "p")
	es := r.k.Log().Entries()
	if last := es[len(es)-1]; last.Type != kernel.TPoolReset {
		t.Fatalf("last entry %s, want the window's reset", last.Type)
	}
	got, err := kernel.Rederive(r.anchors(), r.head.pub, es)
	if err != nil || got.Checked[kernel.TPoolReset] != 1 {
		t.Fatalf("rederive: %v, checked %v, want the reset checked once", err, got.Checked)
	}
}

// A pool entry whose body does not parse folds as corrupt, never as an
// empty reading, reset or reserve.
func TestPoolEntriesWithBadBodiesFoldAsCorrupt(t *testing.T) {
	for _, typ := range []string{kernel.TPoolRead, kernel.TPoolReset, kernel.TReserveUp} {
		s := kernel.NewState(nil)
		if err := s.Apply(kernel.Entry{Seq: 1, Type: typ, Body: []byte(`"x"`)}); !errors.Is(err, kernel.ErrCorrupt) {
			t.Errorf("%s with a bad body: %v, want %v", typ, err, kernel.ErrCorrupt)
		}
	}
}

// A reading's use outside 0..PoolFull is dropped, not stored.
func TestPoolReadDropsOutOfRangeUse(t *testing.T) {
	s := kernel.NewState(nil)
	b := fmt.Sprintf(`{"pool":"p","windows":[{"window":"5h","used":%d,"reset_at":5},{"window":"7d","used":-1,"reset_at":5}]}`, kernel.PoolFull+1)
	if err := s.Apply(kernel.Entry{Seq: 1, Type: kernel.TPoolRead, Body: []byte(b)}); err != nil {
		t.Fatal(err)
	}
	if w := s.Pools["p"].Windows; len(w) != 0 {
		t.Fatalf("windows %+v, want none", w)
	}
}

// Windows due together reset in name order, so a replay of the same state
// logs the same entries.
func TestDueResetsLogInWindowOrder(t *testing.T) {
	names := []string{"a", "b", "c", "d", "e", "f"}
	for range 10 {
		r := newRig(t)
		must(t, r.k.Reserve(1, "p", 100))
		var ws []kernel.WindowReading
		for _, n := range names {
			ws = append(ws, kernel.WindowReading{Window: n, Used: 950, ResetAt: 1_000})
		}
		must(t, r.k.ReadPool(2, "p", ws))
		r.k.AdmitPool(1_000, "p")
		var got []string
		for _, e := range r.k.Log().Entries() {
			if e.Type == kernel.TPoolReset {
				got = append(got, string(e.Body))
			}
		}
		var want []string
		for _, n := range names {
			want = append(want, `{"pool":"p","window":"`+n+`"}`)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("resets %q, want %q", got, want)
		}
	}
}
