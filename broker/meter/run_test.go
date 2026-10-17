package meter

import (
	"errors"
	"testing"
	"time"
)

// REQ: OP-8

// TestOP8PlanRunHasNoCallCap: a provider-agent run on a plan route is
// metered as a run and its wall time, never refused by the machine, task
// or overall cap, and never charged to them: those are money caps on
// pay-per-token API routes (#2291).
func TestOP8PlanRunHasNoCallCap(t *testing.T) {
	small := Limits{Calls: 1, Tokens: 10}
	m, _, n := open(t, Config{MachineCap: small, OverallCap: small, DailyExtension: small})
	if err := call(m, "wk-a", 5, 0); err != nil {
		t.Fatal(err)
	}
	if err := call(m, "wk-a", 5, 0); !errors.Is(err, ErrExhausted) {
		t.Fatalf("API call past the cap: %v", err)
	}
	if err := m.Bind("wk-b", "t1", Limits{Calls: 1, Tokens: 1}); err != nil {
		t.Fatal(err)
	}
	notes := n.count()
	for _, mc := range []string{"wk-a", "wk-b", "wk-c"} {
		for i := 0; i < 5; i++ {
			r, err := m.StartRun(mc)
			if err != nil {
				t.Fatalf("plan run %d on %s refused: %v", i, mc, err)
			}
			r.Done()
		}
	}
	if u := m.Usage("wk-a"); u != (Limits{Calls: 1, Tokens: 5}) {
		t.Errorf("plan runs charged wk-a's money cap: %+v", u)
	}
	if u := m.Usage("wk-c"); u != (Limits{}) {
		t.Errorf("plan runs charged wk-c's money cap: %+v", u)
	}
	if used, _ := m.Overall(); used != (Limits{Calls: 1, Tokens: 5}) {
		t.Errorf("plan runs charged the overall cap: %+v", used)
	}
	if got := m.st.Tasks["t1"].Used; got != (Limits{}) {
		t.Errorf("plan runs charged task t1: %+v", got)
	}
	if n.count() != notes {
		t.Errorf("plan runs sent %d exhaustion notices", n.count()-notes)
	}
	if u := m.RunUsage("wk-a"); u.Runs != 5 {
		t.Errorf("wk-a runs %+v, want 5", u)
	}
}

// TestOP8PlanRunCountsRunsAndWallTime: runs and wall time are counted
// per machine in the rolling window, kept across a restart, and leave
// with the window. Done settles once.
func TestOP8PlanRunCountsRunsAndWallTime(t *testing.T) {
	m, c, _ := open(t, Config{MachineCap: big, OverallCap: big})
	r, err := m.StartRun("wk-a")
	if err != nil {
		t.Fatal(err)
	}
	if u := m.RunUsage("wk-a"); u.Runs != 1 || u.Wall != 0 {
		t.Errorf("in flight %+v", u)
	}
	c.add(90 * time.Second)
	r.Done()
	r.Done()
	if u := m.RunUsage("wk-a"); u.Runs != 1 || u.Wall != 90*time.Second {
		t.Errorf("settled %+v, want 1 run of 90s", u)
	}
	if u := m.RunUsage("wk-b"); u != (RunUse{}) {
		t.Errorf("wk-b %+v", u)
	}
	m2, err := Open(Config{Path: m.cfg.Path, MachineCap: big, OverallCap: big, Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	if u := m2.RunUsage("wk-a"); u.Runs != 1 || u.Wall != 90*time.Second {
		t.Errorf("after reopen %+v", u)
	}
	c.add(25 * time.Hour)
	if u := m2.RunUsage("wk-a"); u != (RunUse{}) {
		t.Errorf("outside the window %+v", u)
	}
}

// TestOP8PlanRunNeedsAMachine: attribution is by machine (OP-8), so a run
// with none is refused rather than counted nowhere.
func TestOP8PlanRunNeedsAMachine(t *testing.T) {
	m, _, _ := open(t, Config{MachineCap: big, OverallCap: big})
	if _, err := m.StartRun(""); err == nil {
		t.Fatal("a run with no machine was counted")
	}
}
