package loops

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// REQ: HLD-4

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

// P6: an owner setting whose save failed does not stop the same setting
// sent again. LOOPS ON (a widening) rolls back and applies when sent again;
// LOOPS OFF (a narrowing) stays in effect unsaved, and sent again it saves.
func TestP6RepeatedOwnerSettingAfterAFailedOne(t *testing.T) {
	for _, first := range []string{"LOOPS OFF", "LOOPS ON"} {
		t.Run(first, func(t *testing.T) {
			ctx := context.Background()
			clk := &clock{t: time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC)}
			spare, _ := newSpare(t, clk.now)
			st := &failingStore{}
			s, err := New(Config{Store: st, Spare: spare, Now: clk.now, Idle: time.Hour, Retry: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			set := func(text string) error {
				t.Helper()
				r, ok := ParseText(text)
				if !ok {
					t.Fatalf("parse %q", text)
				}
				return s.Set(ctx, r, true)
			}
			other := map[string]string{"LOOPS OFF": "LOOPS ON", "LOOPS ON": "LOOPS OFF"}[first]
			if first == "LOOPS ON" {
				must(t, set("LOOPS OFF"))
			}
			st.failAt = st.n + 1
			if err := set(first); err == nil {
				t.Fatalf("%s with a failing save reported saved", first)
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
