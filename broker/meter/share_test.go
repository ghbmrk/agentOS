package meter

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// REQ: OP-8, LOOP-2, LOOP-5
//
// Shares of one meter (the spare budget, loops L3): evaluation keeps a
// reserved share while it has work, which others may borrow while it has
// none and hand back for later calls; a share's Max bounds its own use.

func TestAnActiveReserveIsKeptFromOthers(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: big, OverallCap: Limits{Calls: 10, Tokens: 1000}})
	var evaluating atomic.Bool
	evaluating.Store(true)
	if err := m.SetShares([]Share{{Prefix: "eval-", Reserve: 0.3, Active: evaluating.Load}}); err != nil {
		t.Fatal(err)
	}
	n := 0
	for call(m, "builder", 1, 1) == nil {
		n++
	}
	if n != 7 {
		t.Fatalf("builder made %d calls; 3 of 10 are reserved for evaluation", n)
	}
	for i := 0; i < 3; i++ {
		if err := call(m, "eval-x", 1, 1); err != nil {
			t.Fatalf("evaluation call %d refused: %v", i, err)
		}
	}
	if u := m.ShareUsage("eval-"); u.Calls != 3 {
		t.Fatalf("eval share used %+v", u)
	}
}

func TestAnIdleReserveIsLentAndHandedBack(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: big, OverallCap: Limits{Calls: 10, Tokens: 1000}})
	var evaluating atomic.Bool
	if err := m.SetShares([]Share{{Prefix: "eval-", Reserve: 0.3, Active: evaluating.Load}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if err := call(m, "builder", 1, 1); err != nil {
			t.Fatalf("builder call %d refused while evaluation is idle: %v", i, err)
		}
	}
	evaluating.Store(true)
	if err := call(m, "builder", 1, 1); !errors.Is(err, ErrExhausted) {
		t.Fatalf("builder kept borrowing once evaluation had work: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := call(m, "eval-x", 1, 1); err != nil {
			t.Fatalf("evaluation call %d refused: %v", i, err)
		}
	}
	// Spend already made in the window stays spent: the cap still holds.
	if err := call(m, "eval-x", 1, 1); !errors.Is(err, ErrExhausted) {
		t.Fatalf("call past the overall cap: %v", err)
	}
}

func TestAShareMaxBoundsItsOwnUse(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: big, OverallCap: Limits{Calls: 10, Tokens: 1000}})
	if err := m.SetShares([]Share{
		{Prefix: "eval-", Reserve: 0.3},
		{Prefix: "cleanroom-", Max: 0.2},
	}); err != nil {
		t.Fatal(err)
	}
	n := 0
	for call(m, "cleanroom-1", 1, 1) == nil {
		n++
	}
	if n != 2 {
		t.Fatalf("clean room made %d calls; its share is 2 of 10", n)
	}
	// Max does not stop other work, and the reserve still holds.
	n = 0
	for call(m, "builder", 1, 1) == nil {
		n++
	}
	if n != 5 {
		t.Fatalf("builder made %d calls; 10 less 2 used and 3 reserved is 5", n)
	}
	if err := call(m, "eval-y", 1, 1); err != nil {
		t.Fatalf("evaluation refused its reserve: %v", err)
	}
}

func TestSharesAreValidated(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: big, OverallCap: Limits{Calls: 10, Tokens: 1000}})
	for _, s := range [][]Share{
		{{Prefix: "", Reserve: 0.1}},
		{{Prefix: "a", Reserve: -0.1}},
		{{Prefix: "a", Reserve: 1.1}},
		{{Prefix: "a", Max: 1.5}},
		{{Prefix: "a", Reserve: 0.5, Max: 0.2}},
		{{Prefix: "a", Reserve: 0.6}, {Prefix: "b", Reserve: 0.5}},
		{{Prefix: "eval-"}, {Prefix: "eval-x"}},
	} {
		if err := m.SetShares(s); err == nil {
			t.Fatalf("shares %+v accepted", s)
		}
	}
}

// L3 S4 on #126: a machine's usage is forgotten once its use has left
// the window, so one-job machines (Loop 1's builders, replay) do not pile
// up in the meter's state.
func TestIdleMachinesAreForgotten(t *testing.T) {
	m, c, _ := open(t, Config{MachineCap: big, OverallCap: big})
	if err := call(m, "lb-1", 1, 1); err != nil {
		t.Fatal(err)
	}
	c.add(25 * time.Hour)
	if err := call(m, "lb-2", 1, 1); err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	_, kept := m.st.Machines["lb-1"]
	m.mu.Unlock()
	if kept {
		t.Fatal("a machine idle past the window is still kept")
	}
}
