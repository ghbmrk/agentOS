package sim

// REQ: EVL-1, KRN-1, KRN-5, KRN-6, KRN-7, KRN-8, CLK-2, LOG-2, LOG-4

import (
	"os"
	"reflect"
	"strconv"
	"strings"
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
var traced = map[string]int{}

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
		sum.StopResumed += r.StopResumed
		sum.TasksOpened += r.TasksOpened
		sum.TasksEnded += r.TasksEnded
		sum.EndedEarly += r.EndedEarly
		sum.TaskPlans += r.TaskPlans
		sum.TaskCancels += r.TaskCancels
		sum.TimedOut += r.TimedOut
		sum.KeysWithTasks += r.KeysWithTasks
		sum.TaskKeys += r.TaskKeys
		sum.ReplayedTask += r.ReplayedTask
		sum.CancelledTask += r.CancelledTask
		for _, l := range r.Trace { // the trace names each op it ran
			for _, op := range []string{"stop", "resume at once", "open task", "end task"} {
				if _, rest, ok := strings.Cut(l, " "); ok && (rest == op || strings.HasPrefix(rest, op+" ")) {
					traced[op]++
				}
			}
		}
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
	for _, m := range []Mutant{MutantClerkTrusts, MutantNoDedupe, MutantNoClock} {
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
		"a STOP with a RESUME right after it":          sum.StopResumed,
		"tasks opened":                                 sum.TasksOpened,
		"tasks ended":                                  sum.TasksEnded,
		"tasks the planner ended before their timeout": sum.EndedEarly,
		"plans serving a task":                         sum.TaskPlans,
		"plans their task's end cancelled":             sum.TaskCancels,
		"held steps their task's timeout cancelled":    sum.TimedOut,
		"replayed ids of a task plan":                  sum.ReplayedTask,
		"cancel or undo picks of a task plan":          sum.CancelledTask,
		"traced STOPs":                                 traced["stop"],
		"traced RESUMEs at once":                       traced["resume at once"],
		"traced task opens":                            traced["open task"],
		"traced task ends":                             traced["end task"],
	} {
		if n <= 0 {
			t.Errorf("the sweep never reached: %s", name)
		}
	}
	// Half the STOPs that land are resumed at once, and each such RESUME is
	// logged right after its STOP (taskOp).
	if at, n := traced["resume at once"], traced["stop"]; 4*at < n || 4*at > 3*n || 4*sum.StopResumed < 3*at {
		t.Errorf("%d of %d STOPs resumed at once, %d logged so, want about half, all logged", at, n, sum.StopResumed)
	}
	// A third of the keys drawn while a task is open serve one (derived).
	if k, n := sum.TaskKeys, sum.KeysWithTasks; 4*k < n || 12*k > 5*n {
		t.Errorf("%d of %d keys drawn while a task was open serve one, want about a third", k, n)
	}
}

// SIM-erase (docs/migration/cases.md §4): for each seed, a crash at every
// durable write of the erase phase in turn, until a run reaches no crash.
// Each run ends with one subject.erased per erase, one erase.confirmed per
// store that held an item, no erased key in the table, no erased item
// readable or stored, every kept item readable, and a rebuilt state equal
// to the live one, and no reader's plan from after its first read live
// (RunErase). The crashes must fall on each kind of write.
func TestSimEraseReachesEveryViewOnce(t *testing.T) {
	hits, erased := map[string]int{}, 0
	for seed := 0; seed < seeds(); seed++ {
		for at := 1; ; at++ {
			r, err := RunErase(uint64(seed), at)
			if err != nil {
				t.Fatalf("seed %d crash at write %d: %v", seed, at, err)
			}
			erased += r.Erased
			if !r.Crashed {
				break
			}
			hits[r.Hit]++
		}
		if _, err := RunErase(uint64(seed), 0); err != nil {
			t.Fatalf("seed %d, no crash: %v", seed, err)
		}
	}
	if erased == 0 {
		t.Error("no erase cancelled a reader's plan")
	}
	for _, kind := range []string{"log", "key", "store"} {
		if hits[kind] == 0 {
			t.Errorf("no crash fell on a %s write", kind)
		}
	}
	t.Logf("crashes by write: %v", hits)
}
