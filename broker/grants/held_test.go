package grants

import (
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/reversible"
)

// REQ: REV-3, CH-16, UPD-6

// TestHeldUntilIsTheLastHeldRelease (UX-76-2): the updater's planned
// restart asks the gate when the last effect the owner approved under an
// undo window is released, since a restart would cancel it (RV6). Only
// approved, held effects count: one still waiting for the owner does not,
// and neither does one released or undone.
func TestHeldUntilIsTheLastHeldRelease(t *testing.T) {
	r := newRig(t, withForms(map[string]reversible.Form{"invoice.send": {}}))
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	if !r.g.HeldUntil().IsZero() {
		t.Fatal("held with nothing approved")
	}
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	if !r.g.HeldUntil().IsZero() {
		t.Fatal("an effect waiting for the owner counts as held")
	}
	r.approveHeld()
	first := r.now().Add(reversible.DefaultWindow)
	if got := r.g.HeldUntil(); !got.Equal(first) {
		t.Fatalf("held until %s, want %s", got, first)
	}
	r.advance(4 * time.Minute)
	r.effect("agent/s2", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	h := r.approveHeld()
	second := r.now().Add(reversible.DefaultWindow)
	if got := r.g.HeldUntil(); !got.Equal(second) {
		t.Fatalf("held until %s, want the later release %s", got, second)
	}
	// UNDO of the later one leaves the earlier one.
	r.g.Decide(owner.Decision{Request: h[0], Item: 1, Ref: "agent/s2", Why: "undo"})
	r.g.Wait()
	if got := r.g.HeldUntil(); !got.Equal(first) {
		t.Fatalf("after UNDO held until %s, want %s", got, first)
	}
	// Released: nothing is held.
	r.advance(reversible.DefaultWindow)
	r.g.Tick()
	r.g.Wait()
	if got := r.g.HeldUntil(); !got.IsZero() {
		t.Fatalf("held until %s after the release", got)
	}
}
