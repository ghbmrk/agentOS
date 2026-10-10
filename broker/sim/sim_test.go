package sim

// The harness half of SIM-sim: a seeded run of the real journal engine on a
// fake disk, clock and services. Judging each run by the SIM-check
// predicates is the second half; Config.Judge is where they plug in.
//
// REQ: OP-3, OP-4, OP-5, CAP-3

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

// sweep is the bounded seed sweep CI runs. SIM_SEEDS widens it locally or in
// the soak job.
func sweep() int {
	if n, err := strconv.Atoi(os.Getenv("SIM_SEEDS")); err == nil && n > 0 {
		return n
	}
	return 100
}

func TestSameSeedGivesAByteIdenticalJournal(t *testing.T) {
	for seed := int64(1); seed <= 5; seed++ {
		a := Run(Config{Seed: seed})
		b := Run(Config{Seed: seed})
		if a.Err != nil {
			t.Fatalf("seed %d: %v", seed, a.Err)
		}
		if len(a.Journal) == 0 {
			t.Fatalf("seed %d: empty journal", seed)
		}
		if !bytes.Equal(a.Journal, b.Journal) {
			t.Fatalf("seed %d: journals differ between two runs", seed)
		}
		if strings.Join(a.Trace, "\n") != strings.Join(b.Trace, "\n") {
			t.Fatalf("seed %d: traces differ between two runs", seed)
		}
	}
}

func TestDifferentSeedsGiveDifferentRuns(t *testing.T) {
	if bytes.Equal(Run(Config{Seed: 1}).Journal, Run(Config{Seed: 2}).Journal) {
		t.Fatal("seeds 1 and 2 gave the same journal")
	}
}

// The bounded sweep CI runs finds no violation, and exercises what it
// claims to: crashes at every kind of write point, power cuts, OP-3 races,
// STOP, erasure and reconciliation.
func TestSeedSweepFindsNoViolation(t *testing.T) {
	want := []string{
		"crash write", "crash fsync", "crash rename", "crash dirsync", "crash during open",
		"reboot power", "reboot kill", "nested revoke", "nested stop",
		"recheck_failed", "erase ok", "reconcile", "resolve ok", "outcome_unknown",
	}
	seen := map[string]bool{}
	for seed := int64(1); seed <= int64(sweep()); seed++ {
		r := Run(Config{Seed: seed})
		if r.Err != nil {
			t.Fatalf("%v\nreplay: SIM_SEED=%d go test ./sim -run TestReplaySeed -v", r.Err, seed)
		}
		all := strings.Join(r.Trace, "\n")
		for _, w := range want {
			if strings.Contains(all, w) {
				seen[w] = true
			}
		}
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("no run in the sweep reached %q", w)
		}
	}
}

// A failing seed replays exactly: the same violation at the same step, with
// the same trace.
func TestAFailingSeedReplaysExactly(t *testing.T) {
	seed, first := firstFailure(t, MutantNoRecheck, 50)
	again := Run(Config{Seed: seed, Mutant: MutantNoRecheck})
	if again.Err == nil || again.Err.Error() != first.Err.Error() {
		t.Fatalf("seed %d: replay gave %v, first run %v", seed, again.Err, first.Err)
	}
	if strings.Join(again.Trace, "\n") != strings.Join(first.Trace, "\n") || !bytes.Equal(again.Journal, first.Journal) {
		t.Fatalf("seed %d: replay diverged", seed)
	}
}

// Known bugs reintroduced as mutants are found within a fixed seed budget.
func TestMutantsAreFoundWithinTheSeedBudget(t *testing.T) {
	cases := []struct {
		m    Mutant
		rule string
	}{
		{MutantNoRecheck, "OP-3"},  // dispatch skips the recheck
		{MutantSkipFsync, "OP-4"},  // Append returns before the line is durable
		{MutantTornErase, "CAP-3"}, // the erase rewrite is acknowledged before the directory is synced
	}
	for _, c := range cases {
		_, r := firstFailure(t, c.m, 50)
		var v *Violation
		if !errors.As(r.Err, &v) || v.Rule != c.rule {
			t.Errorf("%s: first violation %v, want rule %s", c.m, r.Err, c.rule)
		}
	}
}

func TestJudgeSeesEveryRebootAndTheEnd(t *testing.T) {
	calls := 0
	r := Run(Config{Seed: 7, Judge: func(j []byte) error {
		calls++
		if len(j) == 0 {
			return nil
		}
		if j[len(j)-1] != '\n' {
			return errors.New("judge saw a torn tail; Open should have cut it")
		}
		return nil
	}})
	if r.Err != nil {
		t.Fatal(r.Err)
	}
	if calls < 2 {
		t.Fatalf("judge called %d times, want at least the first boot and the end", calls)
	}
	bad := Run(Config{Seed: 7, Judge: func([]byte) error { return errors.New("no") }})
	var v *Violation
	if !errors.As(bad.Err, &v) || v.Rule != "judge" {
		t.Fatalf("a refusing judge gave %v, want a judge violation", bad.Err)
	}
}

// TestReplaySeed replays one seed and prints its trace: SIM_SEED=n.
func TestReplaySeed(t *testing.T) {
	s := os.Getenv("SIM_SEED")
	if s == "" {
		t.Skip("set SIM_SEED to replay a seed")
	}
	seed, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	r := Run(Config{Seed: seed, Mutant: Mutant(os.Getenv("SIM_MUTANT"))})
	for _, l := range r.Trace {
		t.Log(l)
	}
	if r.Err != nil {
		t.Fatal(r.Err)
	}
}

func firstFailure(t *testing.T, m Mutant, budget int64) (int64, Result) {
	t.Helper()
	for seed := int64(1); seed <= budget; seed++ {
		if r := Run(Config{Seed: seed, Mutant: m}); r.Err != nil {
			return seed, r
		}
	}
	t.Fatalf("mutant %s survived %d seeds", m, budget)
	return 0, Result{}
}
