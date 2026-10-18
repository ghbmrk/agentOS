package grants

// The held-install notice names no step and is paced as an update.
// REQ: CH-15, CH-12

import (
	"context"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/owner"
)

// W5-Dc-r23 f1 (#2066): the gate holds an install only when no local page
// exists, so the one notice it sends names no confirm step (CH-12: neither
// the page nor a recovery-key flow exists on this build) and asks nothing.
// With nothing to act on it goes out as an update, which quiet hours may
// hold; the request itself stays pending and is never denied (GR17).
func TestHeldInstallNoticeNamesNoStep(t *testing.T) {
	r, p := changeRig(t)
	r.g.cfg.LocalUI = false
	rep, err := p.ProposeRelease(context.Background(), signed(t, 42, map[string][]byte{"host-image/release": []byte("j")}))
	if err != nil || rep.State != change.StateAwaitingOwner {
		t.Fatalf("%+v %v", rep, err)
	}
	r.g.Flush()
	r.own.mu.Lock()
	defer r.own.mu.Unlock()
	if len(r.own.notes) != 1 || r.own.notes[0] != HeldInstallNotice {
		t.Fatalf("%q", r.own.notes)
	}
	if r.own.classes[0] != owner.ClassUpdate {
		t.Fatalf("notice class %v, want update", r.own.classes[0])
	}
	for _, step := range []string{"confirm", "recovery key", "Reply"} {
		if strings.Contains(HeldInstallNotice, step) {
			t.Fatalf("names %q: %q", step, HeldInstallNotice)
		}
	}
}
