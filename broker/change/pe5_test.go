package change

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// REQ: RES-1, CHG-1, LOOP-10

// PE5 (potency on #111; arbitrator, with security F1 on #103): only an
// interruption a candidate could cause counts toward MaxInterruptions.
// One the host marks as the owner's (ErrOwnerPreempt: STOP, accepted work
// without memory pressure, admission with no room) never strikes a case,
// however often it lands (up to MaxExempt, then the candidate is parked);
// pressure, a revoke and any unknown cause still do. Each cut logs a fixed
// class only (security P5). A guest cannot claim the exemption: the mark is an error value only
// host code attaches, so its text in an error counts like any other.
func TestOnlyCandidateCausableCutsCount(t *testing.T) {
	fixture := func(t Tree, pr Probe) bool {
		return string(pr.Input) == exfilProbe && string(t["skills/greet"]) == "hello"
	}
	cutOnFixture := func(ctx context.Context, t Tree, pr Probe) bool { return fixture(t, pr) }
	type pass struct {
		name   string
		cut    bool   // cancel the context on the fixture's candidate run
		cause  error  // the cancel's cause
		refuse error  // else: refuse the run with this error
		struck bool   // the fixture is struck after more than MaxInterruptions
		class  string // an exempt cut's fixed log class (security P5 on PE5)
	}
	for _, tc := range []pass{
		{name: "owner stop", cut: true, cause: ErrOwnerStop, class: "owner-stop"},
		{name: "owner work", cut: true, cause: ErrOwnerWork, class: "owner-work"},
		{name: "no room for the owner's work", refuse: fmt.Errorf("no room: %w: %w", ErrNoRoomPreempt, ErrInterrupted), class: "no-room"},
		{name: "revoked for the owner's work", refuse: fmt.Errorf("revoked: %w: %w", ErrClassRevoke, ErrInterrupted), class: "class-revoke"},
		{name: "memory pressure", cut: true, cause: ErrPressurePreempt, struck: true},
		{name: "no room while the context is cut for pressure", refuse: fmt.Errorf("no room: %w: %w", ErrNoRoomPreempt, ErrInterrupted), cause: ErrPressurePreempt, struck: true},
		{name: "pressure refusal while the context is cut for the owner", refuse: fmt.Errorf("pressure: %w", ErrInterrupted), cause: ErrOwnerStop, struck: true},
		{name: "unknown cause", cut: true, struck: true},
		{name: "guest text claiming the owner", refuse: fmt.Errorf("guest said %q: %w", ErrOwnerPreempt.Error(), ErrInterrupted), struck: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var logged []string
			e, pe := newPreemptEnv(t, func(c *Config) {
				c.MinHeldOut = 100
				c.Logf = func(f string, a ...any) { mu.Lock(); logged = append(logged, fmt.Sprintf(f, a...)); mu.Unlock() }
			})
			e.cases(12, ClassSkill, "skills/greet", "hello")
			arm := func() context.Context {
				ctx := pe.arm(0)
				pe.mu.Lock()
				if tc.cut {
					pe.cut, pe.cause = cutOnFixture, tc.cause
				} else {
					pe.refuse, pe.refuseErr, pe.cause = fixture, tc.refuse, tc.cause
				}
				pe.mu.Unlock()
				return ctx
			}
			// The first pass that finishes is the verdict: a struck case
			// is failed without running, so nothing cuts that pass.
			var rep Report
			finished := false
			// An owner's cuts are exempt MaxExemptPerCase times per case
			// (PE5b, pe5b_test.go has the rest).
			passes := MaxInterruptions + 2
			if !tc.struck {
				passes = MaxExemptPerCase
			}
			for i := 0; i < passes && !finished; i++ {
				r, err := e.p.Propose(arm(), greet)
				switch {
				case err == nil:
					if !tc.struck || i != MaxInterruptions {
						t.Fatalf("pass %d finished", i)
					}
					rep, finished = r, true
				case !errors.Is(err, ErrInterrupted):
					t.Fatalf("pass %d: %v", i, err)
				}
			}
			if !finished {
				pe.arm(0) // a pass nothing cuts
				r, err := e.p.Propose(context.Background(), greet)
				if err != nil {
					t.Fatalf("clean pass: %v", err)
				}
				rep = r
			}
			if struck := rep.SecurityPassed != rep.Security; struck != tc.struck {
				t.Fatalf("struck %v, want %v: %+v", struck, tc.struck, rep)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, l := range logged {
				if !tc.struck && l != "change: a candidate run was cut short ("+tc.class+"); not counted" {
					t.Fatalf("owner cut logged as %q, want class %s", l, tc.class)
				}
			}
			if tc.struck && len(logged) == 0 {
				t.Fatal("counted cuts not logged")
			}
			for _, l := range logged {
				if strings.Contains(l, "guest said") || strings.Contains(l, exfilProbe) {
					t.Fatalf("log carries more than a fixed class: %q", l)
				}
			}
		})
	}
}

// PE5, security P4: a candidate cut short for the owner MaxExempt times is
// parked. It is never struck and gets no verdict: it is refused at once
// (ErrParked, an interruption, so its pairs are kept) unless the scheduler
// marks the evaluator idle, and its exempt count is never reset, so it
// cannot take the evaluator back from other work. Another candidate is
// unaffected.
func TestOwnerCutCandidateIsParked(t *testing.T) {
	e, pe := newPreemptEnv(t, func(c *Config) { c.MinHeldOut = 100 })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	park(t, e, pe, greet)
	pe.arm(0)
	e.p.mu.Lock()
	seq := e.p.st.Seq
	e.p.mu.Unlock()
	if _, err := e.p.Propose(context.Background(), greet); !errors.Is(err, ErrParked) || !errors.Is(err, ErrInterrupted) {
		t.Fatalf("not parked after %d owner cuts: %v", MaxExempt, err)
	}
	if n := pe.runs(); n != 0 {
		t.Fatalf("a parked candidate ran %d probes", n)
	}
	e.p.mu.Lock()
	spent := e.p.st.Seq != seq
	e.p.mu.Unlock()
	if spent {
		t.Fatal("a parked candidate spent a proposal ID")
	}
	other := Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello there")}}
	if _, err := e.p.Propose(context.Background(), other); errors.Is(err, ErrParked) {
		t.Fatal("another candidate was parked")
	}
	pe.arm(0)
	rep, err := e.p.Propose(WithIdle(context.Background()), greet)
	if err != nil {
		t.Fatalf("idle evaluator: %v", err)
	}
	if rep.SecurityPassed != rep.Security {
		t.Fatalf("owner cuts struck a case: %+v", rep)
	}
	if _, err := e.p.Propose(context.Background(), greet); !errors.Is(err, ErrParked) {
		t.Fatalf("exempt count reset by a finished pass: %v", err)
	}
}

// park cuts c short for the owner MaxExempt times, each time on the
// candidate side of a case not cut before, so no case passes its own
// exempt limit (PE5b), and c is parked.
func park(t *testing.T, e *env, pe *preempting, c Candidate) {
	t.Helper()
	seen := map[string]bool{}
	for i := 0; i < MaxExempt; i++ {
		ctx := pe.arm(0)
		cutOne := false
		pe.mu.Lock()
		pe.cut = func(_ context.Context, tr Tree, pr Probe) bool {
			key, ok := e.p.ProbeTask(pr.ID)
			if !ok {
				key = string(pr.Input)
			}
			if cutOne || string(tr["skills/greet"]) != string(c.Files["skills/greet"]) || seen[key] {
				return false
			}
			cutOne, seen[key] = true, true
			return true
		}
		pe.cause = ErrOwnerWork
		pe.mu.Unlock()
		if _, err := e.p.Propose(ctx, c); !errors.Is(err, ErrInterrupted) || errors.Is(err, ErrParked) {
			t.Fatalf("cut %d: %v", i, err)
		}
	}
}
