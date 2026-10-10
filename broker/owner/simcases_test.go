package owner

import (
	"fmt"
	"testing"
	"time"
)

// SIM-cases: owner-visible cases taken from the W5-D drafts (briefs/SIM-cases.md),
// written against main's channel rather than the drafts' types.

// REQ: OP-4, CH-15 (SIM-cases: #335, #336, #337 allowance survives restart)
func TestSpentAllowanceSurvivesARestart(t *testing.T) {
	r := pacedRig(t, Pacing{}, 12, 0)
	for i := 1; i <= 3; i++ {
		if err := r.ch.Inform(fmt.Sprintf("Update %d.", i)); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.sentTexts(); len(got) != 3 {
		t.Fatalf("sent before restart: %q", got)
	}
	r.ch = r.open() // restart from saved state
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance %d after restart, want 0", a)
	}
	if err := r.ch.Inform("Update 4."); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("restart refilled the allowance: %q", got)
	}
	if h := r.held(); len(h) != 1 || h[0].Text != "Update 4." {
		t.Fatalf("held: %+v", h)
	}
	r.advance(61 * time.Minute)
	r.ch = r.open()
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != "Update 4." {
		t.Fatalf("after the hour: %q", got)
	}
}
