package loops

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: OP-2, OP-5

// failingStore fails the save numbered failAt (counted from 1).
type failingStore struct {
	change.MemStore
	n, failAt int
}

func (f *failingStore) Save(b []byte) error {
	f.n++
	if f.n == f.failAt {
		return errors.New("disk hiccup")
	}
	return f.MemStore.Save(b)
}

// P6 (journal B8): an owner setting has fixed params, so every LOOPS OFF
// is the same effect. One whose save failed (not_applied) must not stop
// every later one once another went: a setting made after the effect
// went is a new send. The same holds for LOOPS ON, which widens.
func TestP6RepeatedOwnerSettingAfterAFailedOne(t *testing.T) {
	for _, first := range []string{"LOOPS OFF", "LOOPS ON"} {
		t.Run(first, func(t *testing.T) {
			ctx := context.Background()
			clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
			spare, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "spare.json"),
				MachineCap: meter.Limits{Calls: 50, Tokens: 500_000}, OverallCap: SpareLimits(DefaultSpareCalls), Now: clk.now})
			if err != nil {
				t.Fatal(err)
			}
			st := &failingStore{}
			s, err := New(Config{Store: st, Spare: spare, Now: clk.now, Idle: time.Hour, Retry: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			eng, err := journal.Open(&journal.MemStore{}, s, map[string]journal.Executor{Executor: s},
				func(x string) string { return x }, journal.WithClock(clk.now))
			if err != nil {
				t.Fatal(err)
			}
			s.Attach(eng)
			set := func(text string) error {
				t.Helper()
				r, ok := ParseText(text)
				if !ok {
					t.Fatalf("parse %q", text)
				}
				return s.Set(ctx, r)
			}
			other := map[string]string{"LOOPS OFF": "LOOPS ON", "LOOPS ON": "LOOPS OFF"}[first]
			// Set saves its sequence, then the executor saves the setting:
			// fail the second.
			st.failAt = st.n + 2
			if err := set(first); err == nil {
				t.Fatalf("%s with a failing save went", first)
			}
			for i, text := range []string{first, other, first, other, first} {
				if err := set(text); err != nil {
					t.Fatalf("step %d, %s: %v", i, text, err)
				}
			}
			if s.Settings().Off != (first == "LOOPS OFF") {
				t.Fatalf("settings %+v", s.Settings())
			}
		})
	}
}
