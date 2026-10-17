package grants

// The Wi-Fi page waiting notice is paced like the request it announces.
// REQ: CH-15, CH-12

import (
	"context"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/owner"
)

// W5-Dc-r23 (#989): with no local page reachable by text, the one notice that
// a change waits for the Wi-Fi page or the recovery key goes out as an
// approval-class text, not an update that quiet hours hold past its expiry.
func TestPageWaitNoticeIsApprovalClass(t *testing.T) {
	r, p := changeRig(t)
	r.g.cfg.LocalUI = false
	rep, err := p.ProposeRelease(context.Background(), signed(t, 42, map[string][]byte{"host-image/release": []byte("j")}))
	if err != nil || rep.State != change.StateAwaitingOwner {
		t.Fatalf("%+v %v", rep, err)
	}
	r.g.Flush()
	r.own.mu.Lock()
	defer r.own.mu.Unlock()
	if len(r.own.notes) != 1 || r.own.notes[0] != "Waiting for your confirmation on my Wi-Fi page, or your recovery key." {
		t.Fatalf("%q", r.own.notes)
	}
	if r.own.classes[0] != owner.ClassApproval {
		t.Fatalf("notice class %v, want approval", r.own.classes[0])
	}
}
