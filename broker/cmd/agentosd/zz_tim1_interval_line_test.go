package main

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clock"
)

// REQ: TIM-1, LOG-8

// TIM-1-interval-fu-b (#5279): agentosd's STATUS time check line is the
// clock package's interval line, so it names the moves a wide interval
// delays and its lift, never the removed restricted mode.
func TestTIM1StatusLineIsTheInterval(t *testing.T) {
	since := time.Date(2026, 11, 28, 9, 30, 0, 0, time.UTC)
	cases := []clock.Status{
		{State: clock.Disagree, Skew: 2 * time.Hour, Since: since, Verified: true},
		{State: clock.Disagree, Since: since, Verified: true},
		{State: clock.Disagree, Skew: 2 * time.Hour, Since: since, Verified: true, Authenticated: true},
		{State: clock.Disagree, Since: since, Verified: true, Authenticated: true},
		{State: clock.Held, Skew: time.Hour, Since: since, Verified: true},
		{State: clock.NetworkOnly, Verified: true},
		{State: clock.CarrierOnly, Verified: true},
		{State: clock.NetworkOnly, Start: since},
		{State: clock.Unchecked, Verified: true},
	}
	for _, s := range cases {
		l := clockLine(s, time.UTC)
		if want := s.IntervalLine(time.UTC); l != want {
			t.Errorf("%+v: STATUS line %q, want the interval line %q", s, l, want)
		}
		if strings.Contains(strings.ToLower(l), "restricted") {
			t.Errorf("%+v: STATUS line names the restricted mode: %q", s, l)
		}
	}
	// A plain disagreement names what waits and what lifts it (LOG-8).
	l := clockLine(cases[0], time.UTC)
	for _, w := range []string{"holds and timeouts end by both clocks", "expiries by either", "until they agree", "09:30"} {
		if !strings.Contains(l, w) {
			t.Errorf("disagreement line %q lacks %q", l, w)
		}
	}
	if l := clockLine(clock.Status{State: clock.Agreed, Verified: true}, time.UTC); l != "" {
		t.Errorf("agreed: %q", l)
	}
}

// With no guard open there is no interval: the line says the clock is
// unconfirmed and that agents' questions wait, and names no restricted
// mode (#1246, #5279).
func TestTIM1NoGuardLineNamesNoRestrictedMode(t *testing.T) {
	var q questions
	l := q.Clock()
	if l != clockNotRunning {
		t.Fatalf("no guard: %q", l)
	}
	if !strings.HasPrefix(l, "Time check: not running") || strings.Contains(strings.ToLower(l), "restricted") {
		t.Fatalf("no guard line %q", l)
	}
}
