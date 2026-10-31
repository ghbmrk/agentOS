package codecheck

import (
	"errors"
	"testing"
	"time"
)

// A spent step's write stopped after each privfile.WriteAtomic step, as a
// crash would (REV-CHK-save, #4191), answers no approval and leaves the
// running checker's last step as it was, so a retry of the code verifies
// once and is then spent. The restarted checker holds the step spent only
// if the write got to its rename (step 4); a code that may be spent on disk
// is never taken again.
//
// REQ: CH-4, CH-10, STO-2
func TestASpentStepWriteStoppedAtEveryStep(t *testing.T) {
	for i := 0; i < 6; i++ {
		clk := &clock{t: time.Unix(1_800_000_000, 0)}
		c, state := newChecker(t, clk)
		seed := syntheticSeed()
		open(t, c, seed, 0)
		c.writeStop = func(j int) bool { return j == i }
		r, err := c.Verify(code(seed, clk.now()), 0, true, steps(1))
		if !errors.Is(err, errState) || r.OK || r.Approval != nil {
			t.Fatalf("stopped after step %d: %+v, %v; want refused with no approval", i, r, err)
		}
		if c.last != 0 {
			t.Fatalf("stopped after step %d: the running checker spent step %d", i, c.last)
		}

		re, err := New(Config{StatePath: state, Now: clk.now}) // the restarted checker
		if err != nil {
			t.Fatalf("stopped after step %d: %v", i, err)
		}
		open(t, re, seed, 0)
		if spent := re.last != 0; spent != (i >= 4) {
			t.Fatalf("stopped after step %d: restarted with step %d spent, want spent %v", i, re.last, i >= 4)
		}
		if r, err := re.Verify(code(seed, clk.now()), 0, true, nil); err != nil || r.OK != (i < 4) {
			t.Fatalf("stopped after step %d: the restarted checker answered %+v, %v", i, r, err)
		}

		c.writeStop = nil
		if r, err := c.Verify(code(seed, clk.now()), 0, true, steps(1)); err != nil || !r.OK || r.Approval == nil {
			t.Fatalf("retry after a stop at step %d: %+v, %v", i, r, err)
		}
		if r, err := c.Verify(code(seed, clk.now()), 0, true, steps(1)); err != nil || r.OK {
			t.Fatalf("a third use after a stop at step %d: %+v, %v; want spent", i, r, err)
		}
	}
}
