package sim

// REQ: EVL-1, KRN-1, KRN-5, KRN-6, KRN-7, KRN-8, CLK-2, LOG-2

import (
	"os"
	"reflect"
	"strconv"
	"testing"
)

func seeds() int {
	if n, err := strconv.Atoi(os.Getenv("SIM_SEEDS")); err == nil && n > 0 {
		return n
	}
	return 40
}

func TestSweepHoldsInvariants(t *testing.T) {
	effects := 0
	for seed := 0; seed < seeds(); seed++ {
		r, err := Run(Config{Seed: uint64(seed), Ops: 200})
		if err != nil {
			t.Fatal(err)
		}
		effects += r.Effects
	}
	t.Logf("%d effects over %d seeds", effects, seeds())
	if effects == 0 {
		t.Fatal("the sweep never reached an effect; it proves nothing")
	}
}

func TestSameSeedGivesTheSameLog(t *testing.T) {
	a, err := Run(Config{Seed: 7, Ops: 200})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Run(Config{Seed: 7, Ops: 200})
	if !reflect.DeepEqual(a.Trace, b.Trace) || len(a.Entries) != len(b.Entries) {
		t.Fatal("a seed must replay exactly")
	}
	for i := range a.Entries {
		if a.Entries[i].Hash() != b.Entries[i].Hash() {
			t.Fatalf("entry %d differs", i+1)
		}
	}
}

func TestMutantsAreCaught(t *testing.T) {
	for _, m := range []Mutant{MutantClerkTrusts, MutantNoDedupe} {
		caught := false
		for seed := 0; seed < 100 && !caught; seed++ {
			_, err := Run(Config{Seed: uint64(seed), Ops: 200, Mutant: m})
			caught = err != nil
		}
		if !caught {
			t.Errorf("mutant %q survived 100 seeds", m)
		}
	}
}

// The sweep reaches the faults that real machines have, and each counter moves
// only when the fault changed something: a Fill that refuses nothing, a clock
// that never moves back or a stale request that is not redelivered leaves its
// counter at zero.
func TestSweepFaultsTakeEffect(t *testing.T) {
	var sum Result
	for seed := 0; seed < seeds(); seed++ {
		r, err := Run(Config{Seed: uint64(seed), Ops: 200})
		if err != nil {
			t.Fatal(err)
		}
		sum.Refused += r.Refused
		sum.ClockBack += r.ClockBack
		sum.StaleRefused += r.StaleRefused
		sum.AnchorFailed += r.AnchorFailed
		sum.WidenUnproven += r.WidenUnproven
	}
	for name, n := range map[string]int{
		"appends refused by a full disk":             sum.Refused,
		"clock moves back":                           sum.ClockBack,
		"stale requests refused":                     sum.StaleRefused,
		"anchor writes failed":                       sum.AnchorFailed,
		"widenings left unproven by a failed anchor": sum.WidenUnproven,
	} {
		if n == 0 {
			t.Errorf("the sweep never reached: %s", name)
		}
	}
}
