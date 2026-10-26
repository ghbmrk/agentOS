package sim

// REQ: EVL-1, KRN-1, KRN-5, KRN-6, KRN-7, KRN-8, CLK-2, LOG-2, LOG-4

import (
	"os"
	"reflect"
	"strconv"
	"sync"
	"testing"
)

func seeds() int {
	if n, err := strconv.Atoi(os.Getenv("SIM_SEEDS")); err == nil && n > 0 {
		return n
	}
	return 40
}

// sweep runs every seed once, for the tests that read the sweep, and sums
// their counters; a seed whose invariants fail stops it.
var sweep = sync.OnceValues(func() (Result, error) {
	var sum Result
	for seed := 0; seed < seeds(); seed++ {
		r, err := Run(Config{Seed: uint64(seed), Ops: 200})
		if err != nil {
			return sum, err
		}
		sum.Effects += r.Effects
		sum.Refused += r.Refused
		sum.ClockBack += r.ClockBack
		sum.StaleRefused += r.StaleRefused
		sum.AnchorFailed += r.AnchorFailed
		sum.WidenUnproven += r.WidenUnproven
		sum.UnheldRefused += r.UnheldRefused
		sum.BigRefused += r.BigRefused
		sum.HeldByClerk += r.HeldByClerk
		sum.CutRefused += r.CutRefused
		sum.CutCancelled += r.CutCancelled
	}
	return sum, nil
})

func TestSweepHoldsInvariants(t *testing.T) {
	sum, err := sweep()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d effects over %d seeds", sum.Effects, seeds())
	if sum.Effects == 0 {
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
	sum, err := sweep()
	if err != nil {
		t.Fatal(err)
	}
	for name, n := range map[string]int{
		"appends refused by a full disk":               sum.Refused,
		"clock moves back":                             sum.ClockBack,
		"stale requests refused":                       sum.StaleRefused,
		"anchor writes failed":                         sum.AnchorFailed,
		"widenings left unproven by a failed anchor":   sum.WidenUnproven,
		"plans under a stripped, forged or unheld key": sum.UnheldRefused,
		"big grants refused without a second passkey":  sum.BigRefused,
		"holds the clerk kept on its own clock":        sum.HeldByClerk,
		"grants a cut-off phone signed, refused":       sum.CutRefused,
		"held grants cancelled with their phone":       sum.CutCancelled,
	} {
		if n == 0 {
			t.Errorf("the sweep never reached: %s", name)
		}
	}
}

// SIM-erase (docs/migration/cases.md §4): for each seed, a crash at every
// durable write of the erase phase in turn, until a run reaches no crash.
// Each run ends with one subject.erased per erase, one erase.confirmed per
// store that held an item, no erased key in the table, no erased item
// readable or stored, every kept item readable, and a rebuilt state equal
// to the live one (RunErase). The crashes must fall on each kind of write.
func TestSimEraseReachesEveryViewOnce(t *testing.T) {
	hits := map[string]int{}
	for seed := 0; seed < seeds(); seed++ {
		for at := 1; ; at++ {
			r, err := RunErase(uint64(seed), at)
			if err != nil {
				t.Fatalf("seed %d crash at write %d: %v", seed, at, err)
			}
			if !r.Crashed {
				break
			}
			hits[r.Hit]++
		}
		if _, err := RunErase(uint64(seed), 0); err != nil {
			t.Fatalf("seed %d, no crash: %v", seed, err)
		}
	}
	for _, kind := range []string{"log", "key", "store"} {
		if hits[kind] == 0 {
			t.Errorf("no crash fell on a %s write", kind)
		}
	}
	t.Logf("crashes by write: %v", hits)
}
