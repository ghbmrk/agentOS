package localui

import (
	"net/url"
	"strings"
	"testing"
)

// REQ: UPD-3
// Offline first boot: the page says the box runs the version it shipped
// with and updates when next online, and Connect AI stays held, by the
// page and by the step's handler.
func TestOfflineFirstBootSaysSoAndHoldsAI(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	r.hooks.mu.Lock()
	r.hooks.progress = Progress{Phase: "offline"}
	r.hooks.mu.Unlock()
	page := r.get("/setup")
	for _, want := range []string{"offline (setup can continue)", "version it shipped with", "updates when it is next online"} {
		if !strings.Contains(page, want) {
			t.Fatalf("offline page lacks %q: %s", want, page)
		}
	}
	if strings.Contains(page, `name="key"`) {
		t.Fatal("AI form shown before the update")
	}
	r.post("/setup/ai-key", url.Values{"provider": {"anthropic"}, "key": {apiCanary}, "private": {"1"}})
	if e := r.setupErr(); !strings.Contains(e, "offline") || r.hooks.keys != nil {
		t.Fatalf("AI connected offline, or no reason given: %q", e)
	}
	r.post("/setup/ai-device", url.Values{"provider": {"anthropic"}, "private": {"1"}})
	if strings.Contains(r.get("/setup"), "WXYZ-1234") {
		t.Fatal("device sign-in started offline")
	}
}

// REQ: UPD-3
// Online and still updating: the page says the box is updating first.
func TestUpdatingFirstBootSaysSo(t *testing.T) {
	r := newRig(t)
	r.runSetupToAI()
	r.hooks.mu.Lock()
	r.hooks.progress = Progress{Phase: "updating", Online: true}
	r.hooks.mu.Unlock()
	page := r.get("/setup")
	if !strings.Contains(page, "updating (setup can continue)") || !strings.Contains(page, "The box is updating to the latest version first") {
		t.Fatalf("updating page: %s", page)
	}
}
