package pubid

import (
	"testing"
	"time"
)

// REQ: OSS-6
// OSS-6 W5 (HOST-1b carry): an unverified clock counts no day; the day
// stays unseen so a later release after verification can count it.
func TestOSS6W5UnverifiedClockCountsNoDay(t *testing.T) {
	g := newRig(t, 0)
	var m time.Duration
	g.mono = func() time.Duration { return m }
	g.reopen(t)
	verified := true
	g.p.cfg.Verified = func() bool { return verified }
	// Re-warm under Verified so the chain is counted with the hook set.
	g.warm(t, g.p)
	before := len(g.p.st.Days)
	seen := g.p.st.Seen

	verified = false
	m = 20 * time.Hour
	g.day(1, 5*time.Hour)
	must(t, g.p.Release())
	if g.p.st.Seen != seen || len(g.p.st.Days) != before {
		t.Fatalf("unverified advanced: seen %s want %s, days %d want %d", g.p.st.Seen, seen, len(g.p.st.Days), before)
	}

	verified = true
	g.day(1, 6*time.Hour)
	must(t, g.p.Release())
	if g.p.st.Seen != day(g.c.t) || len(g.p.st.Days) != before+1 {
		t.Fatalf("verified day did not count: seen %s, days %d", g.p.st.Seen, len(g.p.st.Days))
	}
}

// REQ: OSS-6
func TestOSS6W5NilVerifiedKeepsPriorBehavior(t *testing.T) {
	g := newRig(t, 0)
	if g.p.cfg.Verified != nil {
		t.Fatal("default Verified should be nil")
	}
	before := len(g.p.st.Days)
	g.day(1, 5*time.Hour)
	must(t, g.p.Release())
	if len(g.p.st.Days) <= before {
		t.Fatal("nil Verified should still count")
	}
}
