package pubid

// REQ: OSS-6

import (
	"path/filepath"
	"testing"
	"time"
)

// restartRig counts day 1 at monotonic count on boot "b1", then restarts
// the broker on boot with the monotonic clock at m.
func restartRig(t *testing.T, count time.Duration, boot string) (*rig, *time.Duration) {
	t.Helper()
	g := newRig(t, 0)
	m := count
	b := "b1"
	g.mono = func() time.Duration { return m }
	g.boot = func() string { return b }
	g.reopen(t)
	g.day(1, 5*time.Hour)
	must(t, g.p.Release())
	if g.p.st.Seen != day(g.c.t) {
		t.Fatal("day 1 did not count")
	}
	b = boot
	g.reopen(t)
	return g, &m
}

// counts reports whether a release on day 2 at monotonic m counts it.
func counts(t *testing.T, g *rig, m *time.Duration, at time.Duration) bool {
	t.Helper()
	*m = at
	g.day(2, 5*time.Hour+at%time.Hour)
	n := len(g.p.st.Days)
	must(t, g.p.Release())
	return len(g.p.st.Days) == n+1
}

// On the same boot the 20h floor holds across a broker restart: the
// outbox keeps the last count's CLOCK_BOOTTIME and boot_id, so a restart
// cannot let a day count without real time passing (Security on #180).
func TestOSS6FloorHoldsAcrossARestart(t *testing.T) {
	g, m := restartRig(t, 30*time.Hour, "b1")
	if counts(t, g, m, 30*time.Hour+20*time.Hour-time.Second) {
		t.Fatal("a restart on the same boot let a day count inside the floor")
	}
	g.reopen(t) // a second restart changes nothing
	if !counts(t, g, m, 50*time.Hour) {
		t.Fatal("the day did not count at the floor")
	}
}

// A stored count ahead of the current CLOCK_BOOTTIME on the same boot is
// corrupt: it counts no day, and the floor runs from the reading at start,
// so a bad file neither opens the floor nor freezes the outbox (G4).
func TestOSS6StoredCountAheadIsCorrupt(t *testing.T) {
	g, m := restartRig(t, 50*time.Hour, "b1")
	*m = 10 * time.Hour
	g.reopen(t)
	if counts(t, g, m, 30*time.Hour-time.Second) {
		t.Fatal("a stored count ahead of the clock let a day count")
	}
	if !counts(t, g, m, 30*time.Hour) {
		t.Fatal("a stored count ahead of the clock froze the outbox")
	}
}

// A count stored on another boot is ignored: CLOCK_BOOTTIME restarts at
// each boot, so its value says nothing about time since the count.
func TestOSS6CountFromAnotherBootIsIgnored(t *testing.T) {
	g, m := restartRig(t, 50*time.Hour, "b2")
	if !counts(t, g, m, time.Hour) {
		t.Fatal("a count from another boot held the floor")
	}
	g, m = restartRig(t, 5*time.Hour, "b2")
	if !counts(t, g, m, 6*time.Hour) {
		t.Fatal("a count from another boot held the floor")
	}
}

// With no boot named (no boot_id, or a floor clock that is not
// CLOCK_BOOTTIME) nothing is carried across a restart.
func TestOSS6NoBootCarriesNothing(t *testing.T) {
	g, m := restartRig(t, 30*time.Hour, "")
	if g.p.st.Boot != "b1" {
		t.Fatalf("stored boot %q", g.p.st.Boot)
	}
	if !counts(t, g, m, 31*time.Hour) {
		t.Fatal("a count was carried with no boot named")
	}
	if g.p.st.Boot != "" || g.p.st.Counted != 0 {
		t.Fatalf("a count with no boot named was stored: %q %v", g.p.st.Boot, g.p.st.Counted)
	}
}

// A boot named without the monotonic clock it goes with is refused: the
// stored count is only meaningful against that boot's CLOCK_BOOTTIME.
func TestOSS6BootIDNeedsItsClock(t *testing.T) {
	g := newRig(t, 0)
	_, err := NewPublisher(Config{
		Path: filepath.Join(g.dir, "outbox.json"), Identity: g.id, Sender: g.out, Now: g.c.now,
		Signers: map[string]Signer{"artifact": signer}, BootID: func() string { return "b1" },
	})
	if err == nil {
		t.Fatal("a boot id without its clock was accepted")
	}
}

// A malformed stored count refuses the outbox, like any other malformed
// field (MUST 2 on #163).
func TestOSS6MalformedStoredCountRefused(t *testing.T) {
	g, _ := restartRig(t, 30*time.Hour, "b1")
	for _, st := range []outbox{
		{Boot: "b1", Counted: -time.Second},
		{Boot: "", Counted: time.Hour},
		{Boot: string(make([]byte, 65)), Counted: time.Hour},
	} {
		g.p.st = st
		must(t, g.p.save())
		if _, err := NewPublisher(Config{
			Path: filepath.Join(g.dir, "outbox.json"), Identity: g.id, Sender: g.out, Now: g.c.now,
			Signers: map[string]Signer{"artifact": signer}, Mono: g.mono, BootID: g.boot,
		}); err == nil {
			t.Errorf("stored count %+v loaded", st)
		}
	}
}
