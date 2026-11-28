package main

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/control"
)

// REQ: TIM-1, LOG-8

// statusNote is note as control.Handler's STATUS reply shows it.
func statusNote(note string) string {
	h := &control.Handler{Engine: statusEngine{}, Auth: statusOwner{}, Notes: []func() string{func() string { return note }}}
	return h.Status()
}

// TIM-1-interval-fu-b (#5279, #6754 UX 1): every STATUS time check line
// reaches the owner whole through control.Handler (100 characters, its
// alphabet), names no restricted mode, and a disagreement names what waits
// and its lift (LOG-8).
func TestTIM1StatusLineIsTheInterval(t *testing.T) {
	since := time.Date(2026, 11, 28, 9, 30, 0, 0, time.UTC)
	skews := []time.Duration{6 * time.Minute, 59 * time.Minute, time.Hour, 47 * time.Hour, 99 * 24 * time.Hour, 100 * 24 * time.Hour, math.MaxInt64, math.MinInt64}
	var cases []clock.Status
	for _, sk := range skews {
		for _, auth := range []bool{false, true} {
			cases = append(cases, clock.Status{State: clock.Disagree, Skew: sk, Since: since, Verified: true, Authenticated: auth})
		}
		cases = append(cases, clock.Status{State: clock.Held, Skew: sk, Since: since, Verified: true})
	}
	cases = append(cases,
		clock.Status{State: clock.Disagree, Since: since, Verified: true},
		clock.Status{State: clock.Disagree, Since: since, Verified: true, Authenticated: true},
		clock.Status{State: clock.NetworkOnly, Verified: true},
		clock.Status{State: clock.CarrierOnly, Verified: true},
		clock.Status{State: clock.NetworkOnly, Start: since},
		clock.Status{State: clock.Unchecked, Verified: true},
	)
	for _, s := range cases {
		l := clockLine(s, time.UTC)
		if len(l) > 100 || !strings.HasSuffix(statusNote(l), " "+l) {
			t.Errorf("%+v: line %q (%d characters) does not reach STATUS whole: %q", s, l, len(l), statusNote(l))
		}
		if !strings.HasPrefix(l, "Time check: ") || strings.Contains(strings.ToLower(l), "restricted") {
			t.Errorf("%+v: line %q", s, l)
		}
	}
	for _, c := range []struct {
		s    clock.Status
		want []string
	}{
		{clock.Status{State: clock.Disagree, Skew: 2 * time.Hour, Since: since, Verified: true}, []string{"2 hours since 09:30", "holds and timeouts wait", "until clocks agree"}},
		{clock.Status{State: clock.Disagree, Since: since, Verified: true}, []string{"unreadable since 09:30", "holds and timeouts wait", "until time is confirmed"}},
		{clock.Status{State: clock.Disagree, Skew: -90 * time.Minute, Since: since, Verified: true, Authenticated: true}, []string{"1 hour since 09:30", "authenticated network time stands"}},
		{clock.Status{State: clock.Held, Skew: 10 * time.Minute, Since: since, Verified: true}, []string{"10 minutes at 09:30", "my own count of time stands"}},
		{clock.Status{State: clock.Disagree, Skew: 3 * 24 * time.Hour, Since: since, Verified: true}, []string{"3 days"}},
		{clock.Status{State: clock.Disagree, Skew: math.MinInt64, Since: since, Verified: true}, []string{"over 99 days"}},
	} {
		if l := clockLine(c.s, time.UTC); !containsAll(l, c.want) {
			t.Errorf("%+v: line %q lacks one of %q", c.s, l, c.want)
		}
	}
	if l := clockLine(clock.Status{State: clock.Agreed, Verified: true}, time.UTC); l != "" {
		t.Errorf("agreed: %q", l)
	}
}

func containsAll(s string, subs []string) bool {
	for _, w := range subs {
		if !strings.Contains(s, w) {
			return false
		}
	}
	return true
}

// With no guard open there is no interval: the line says what waits and
// names no restricted mode, and reaches STATUS whole (#1246, #5279).
func TestTIM1NoGuardLineNamesNoRestrictedMode(t *testing.T) {
	var q questions
	l := q.Clock()
	if l != clockNotRunning || !strings.HasPrefix(l, "Time check: not running") || strings.Contains(strings.ToLower(l), "restricted") {
		t.Fatalf("no guard line %q", l)
	}
	if !containsAll(l, []string{"updates wait", "cannot ask you questions"}) || len(l) > 100 || !strings.HasSuffix(statusNote(l), " "+l) {
		t.Fatalf("no guard line %q reaches STATUS as %q", l, statusNote(l))
	}
}
