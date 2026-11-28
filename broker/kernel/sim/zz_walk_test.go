package sim_test

// REQ: EVL-1

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/sim"
)

// walk is a digest of everything one run leaves: its trace, every counter,
// and each log entry's hash (which covers its body, its signature and the
// nonces drawn for it).
func walk(r *sim.Result) string {
	h := sha256.New()
	for _, l := range r.Trace {
		fmt.Fprintf(h, "%s\n", l)
	}
	entries(h, r.Entries)
	c := *r
	c.Trace, c.Entries = nil, nil
	fmt.Fprintf(h, "%+v", c)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// entries writes each entry's hash to h.
func entries(h hash.Hash, es []kernel.Entry) {
	for _, e := range es {
		eh := e.Hash()
		h.Write(eh[:])
	}
}

// pinned compares each digest got[i] with want[i], or logs them all under
// SIM_WALK=print.
func pinned(t *testing.T, what string, got, want []string) {
	t.Helper()
	if os.Getenv("SIM_WALK") == "print" {
		for i, g := range got {
			t.Logf("%q, // %s %d", g, what, i)
		}
		return
	}
	if len(got) != len(want) {
		t.Fatalf("%d %ss walked, %d pinned", len(got), what, len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s %d walked %s, pinned %s: a change moved the walk (SIM_WALK=print records it again)", what, i, got[i], want[i])
		}
	}
}

// One seed gives one trace, byte for byte (SIM-1), and that trace is pinned:
// each seed below must replay the walk it gave when it was recorded, its
// faults, owner actions, planner steps and log included. A change to the
// planner, the world or the kernel that moves any walk fails here, so it is
// made on purpose and the digests recorded again: run with SIM_WALK=print
// and paste the lines it logs. Catches a planner op, fault or setup step that
// silently stopped happening, which the invariants alone cannot see.
func TestEachSeedWalksItsPinnedPath(t *testing.T) {
	want := []string{
		"e2e39a11554cb542", "eb6e019e057d841f", "66de116140da3e49", "96edc32b236a39d1",
		"3de6a691f8269c92", "41c051f7dec4cff6", "4078b5ee2cad7e60", "7762cb49620b46cc",
	}
	var got []string
	for seed := range want {
		r, err := sim.Run(sim.Config{Seed: uint64(seed), Ops: 200})
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		got = append(got, walk(r))
	}
	pinned(t, "seed", got, want)
}

// The erase phase is pinned the same way (SIM-erase): for each seed, the
// crash at each of its writes in turn and the run with none, each run's
// outcome and the log it ended with, in one digest per seed.
func TestEachEraseSeedWalksItsPinnedPath(t *testing.T) {
	want := []string{
		"299fad70c0c05ade", "9f7fd4b6bdc81e22", "52ba923f3683813d", "1c6272be534d2a8f",
	}
	var got []string
	for seed := range want {
		h := sha256.New()
		for at := 0; ; at++ {
			r, err := sim.RunErase(uint64(seed), at)
			if err != nil {
				t.Fatalf("seed %d crash at write %d: %v", seed, at, err)
			}
			fmt.Fprintf(h, "%d %v %q %d\n", at, r.Crashed, r.Hit, r.Erased)
			entries(h, r.Log)
			if at > 0 && !r.Crashed {
				break
			}
		}
		got = append(got, hex.EncodeToString(h.Sum(nil))[:16])
	}
	pinned(t, "erase seed", got, want)
}
