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
// however often it lands; pressure, a revoke and any unknown cause still
// do. A guest cannot claim the exemption: the mark is an error value only
// host code attaches, so its text in an error counts like any other.
func TestOnlyCandidateCausableCutsCount(t *testing.T) {
	fixture := func(t Tree, pr Probe) bool {
		return string(pr.Input) == exfilProbe && string(t["skills/greet"]) == "hello"
	}
	cutOnFixture := func(ctx context.Context, t Tree, pr Probe) bool { return fixture(t, pr) }
	type pass struct {
		name   string
		cut    bool  // cancel the context on the fixture's candidate run
		cause  error // the cancel's cause
		refuse error // else: refuse the run with this error
		struck bool  // the fixture is struck after more than MaxInterruptions
	}
	for _, tc := range []pass{
		{name: "owner preemption", cut: true, cause: ErrOwnerPreempt},
		{name: "no room for the owner's work", refuse: fmt.Errorf("no room: %w: %w", ErrOwnerPreempt, ErrInterrupted)},
		{name: "memory pressure", cut: true, cause: ErrPressurePreempt, struck: true},
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
					pe.refuse, pe.refuseErr = fixture, tc.refuse
				}
				pe.mu.Unlock()
				return ctx
			}
			// The first pass that finishes is the verdict: a struck case
			// is failed without running, so nothing cuts that pass.
			var rep Report
			finished := false
			for i := 0; i < MaxInterruptions+2 && !finished; i++ {
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
			if !tc.struck && len(logged) != 0 {
				t.Fatalf("owner cuts logged as counted: %q", logged)
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
