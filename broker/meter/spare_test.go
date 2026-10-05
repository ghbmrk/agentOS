package meter

import (
	"errors"
	"testing"
)

// REQ: OP-8, LOOP-2
//
// A meter whose overall cap is an owner setting (the loops' spare budget):
// Overall reports use against the cap, and a lowered cap holds the next
// call, whichever machine makes it.

func TestOverallCapCanBeLoweredAndRaised(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: big, OverallCap: Limits{Calls: 10, Tokens: 1000}})
	for i := 0; i < 3; i++ {
		if err := call(m, "eval-a", 10, 10); err != nil {
			t.Fatal(err)
		}
	}
	used, limit := m.Overall()
	if used.Calls != 3 || used.Tokens != 60 || limit.Calls != 10 {
		t.Fatalf("Overall = %+v of %+v", used, limit)
	}
	if err := m.SetOverallCap(Limits{Calls: 3, Tokens: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := call(m, "eval-b", 10, 10); !errors.Is(err, ErrExhausted) {
		t.Fatalf("call past a lowered cap: %v", err)
	}
	if err := m.SetOverallCap(Limits{Calls: 4, Tokens: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := call(m, "eval-c", 10, 10); err != nil {
		t.Fatalf("call under a raised cap: %v", err)
	}
	for _, l := range []Limits{{Calls: 0, Tokens: 1}, {Calls: 1, Tokens: 0}} {
		if err := m.SetOverallCap(l); err == nil {
			t.Fatalf("cap %+v accepted: there is no unlimited setting", l)
		}
	}
}
