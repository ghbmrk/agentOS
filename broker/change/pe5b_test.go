package change

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// REQ: RES-1, CHG-1, LOOP-1

// cutFixture arms pe to cut the fixture's candidate-side run for the
// owner's work.
func cutFixture(pe *preempting) context.Context {
	ctx := pe.arm(0)
	pe.mu.Lock()
	pe.cut = func(_ context.Context, t Tree, pr Probe) bool {
		return string(pr.Input) == exfilProbe && string(t["skills/greet"]) == "hello"
	}
	pe.cause = ErrOwnerWork
	pe.mu.Unlock()
	return ctx
}

// PE5b (security B2 on #127): an owner's cut of one (candidate, case)
// pair is exempt MaxExemptPerCase times. The next counts as an ordinary
// interruption under MaxInterruptions, logged by its fixed class, so owner
// cuts cannot re-roll a case without limit.
func TestThirdOwnerCutOfACaseCounts(t *testing.T) {
	var mu sync.Mutex
	var logged []string
	e, pe := newPreemptEnv(t, func(c *Config) {
		c.MinHeldOut = 100
		c.Logf = func(f string, a ...any) { mu.Lock(); logged = append(logged, fmt.Sprintf(f, a...)); mu.Unlock() }
	})
	e.cases(12, ClassSkill, "skills/greet", "hello")
	for i := 0; i < MaxExemptPerCase+MaxInterruptions; i++ {
		if _, err := e.p.Propose(cutFixture(pe), greet); !errors.Is(err, ErrInterrupted) {
			t.Fatalf("cut %d: %v", i, err)
		}
	}
	mu.Lock()
	past := 0
	for _, l := range logged {
		if l == "change: a candidate run was cut short (owner-work, past its exempt limit); counted" {
			past++
		}
	}
	mu.Unlock()
	if past != MaxInterruptions {
		t.Fatalf("%d cuts past the exempt limit logged as counted, want %d: %q", past, MaxInterruptions, logged)
	}
	pe.arm(0)
	rep, err := e.p.Propose(context.Background(), greet)
	if err != nil {
		t.Fatalf("clean pass: %v", err)
	}
	if rep.SecurityPassed == rep.Security {
		t.Fatalf("owner cuts past the per-case limit did not strike the case: %+v", rep)
	}
}

// PE5b: the per-case cut counts are saved with the pipeline's state, so a
// restart does not reset them, and they hold only counts and a time.
func TestCutCountsSurviveARestart(t *testing.T) {
	var cfg *Config
	e, pe := newPreemptEnv(t, func(c *Config) { c.MinHeldOut = 100; cfg = c })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	for i := 0; i < MaxExemptPerCase; i++ {
		if _, err := e.p.Propose(cutFixture(pe), greet); !errors.Is(err, ErrInterrupted) {
			t.Fatalf("cut %d: %v", i, err)
		}
	}
	raw, _ := e.store.Load()
	if !strings.Contains(string(raw), `"cuts"`) || strings.Contains(string(raw), exfilProbe) {
		t.Fatalf("saved state: cut counts missing or carrying case content")
	}
	p, err := New(*cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.open(p)
	for i := 0; i < MaxInterruptions; i++ {
		if _, err := e.p.Propose(cutFixture(pe), greet); !errors.Is(err, ErrInterrupted) {
			t.Fatalf("cut %d after restart: %v", i, err)
		}
	}
	pe.arm(0)
	rep, err := e.p.Propose(context.Background(), greet)
	if err != nil {
		t.Fatalf("clean pass: %v", err)
	}
	if rep.SecurityPassed == rep.Security {
		t.Fatalf("a restart reset the cut counts: %+v", rep)
	}
	e.p.mu.Lock()
	left := len(e.p.st.Cuts)
	e.p.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d cut counts outlived the verdict", left)
	}
}

// PE5b: the idle evaluator takes parked candidates in turns. One that just
// ran idle is not picked again straight away while another parked
// candidate waits; with none waiting it runs again; and one that waited
// once but is not offered again holds it back for one idle pass only.
func TestParkedCandidatesTakeIdleTurns(t *testing.T) {
	e, pe := newPreemptEnv(t, func(c *Config) { c.MinHeldOut = 100; c.DevPercent = parkDev })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := greet
	b := Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello there")}}
	park(t, e, pe, a)
	park(t, e, pe, b)
	idle := WithIdle(context.Background())
	// cutAny cuts the first run of an idle pass, so the candidate stays
	// parked with its turn taken and no verdict.
	cutAny := func() context.Context {
		ctx := pe.arm(1)
		pe.mu.Lock()
		pe.cause = ErrOwnerWork
		pe.mu.Unlock()
		return WithIdle(ctx)
	}
	refused := func(c Candidate) {
		t.Helper()
		if _, err := e.p.Propose(context.Background(), c); !errors.Is(err, ErrParked) {
			t.Fatalf("not parked: %v", err)
		}
	}
	ran := func(ctx context.Context, c Candidate) bool {
		t.Helper()
		_, err := e.p.Propose(ctx, c)
		if errors.Is(err, ErrParked) {
			return false
		}
		if !errors.Is(err, ErrInterrupted) {
			t.Fatalf("idle run: %v", err)
		}
		return true
	}
	// Pass 1: both wait; a takes the idle turn.
	refused(a)
	refused(b)
	if !ran(cutAny(), a) {
		t.Fatal("a parked candidate with no turn yet did not run idle")
	}
	// Pass 2: both wait again; a yields to b.
	refused(a)
	refused(b)
	if ran(idle, a) {
		t.Fatal("a ran again straight away while b waited")
	}
	if !ran(cutAny(), b) {
		t.Fatal("b did not take its turn")
	}
	// Pass 3: a's turn again.
	refused(a)
	refused(b)
	if ran(idle, b) {
		t.Fatal("b ran again straight away while a waited")
	}
	if !ran(cutAny(), a) {
		t.Fatal("a did not take its turn")
	}
	// b waits once more, so a yields; then b is no longer offered, and a
	// waits on it for that one idle pass only.
	refused(a)
	refused(b)
	if ran(idle, a) {
		t.Fatal("a did not yield to b's wait")
	}
	refused(a)
	if !ran(cutAny(), a) {
		t.Fatal("a waited on a candidate no longer offered")
	}
	// With nothing else waiting, a runs idle pass after pass.
	refused(a)
	if !ran(cutAny(), a) {
		t.Fatal("a did not run with nothing else waiting")
	}
}
