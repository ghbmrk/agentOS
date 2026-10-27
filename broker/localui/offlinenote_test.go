package localui

import (
	"strings"
	"testing"
)

// REQ: ONB-4, CH-12
// WIFI-del-offline-note (#3327): the core's only uplink runs through the
// enforcer (HW-12, D-178), and the page answers only on that same cable,
// so an offline core that the owner can read names the step past the
// enforcer, on every page that says it is offline, from the first setup
// step on.
func TestOfflineNamesTheStepPastTheEnforcer(t *testing.T) {
	const step = "I can reach your home control box but not the internet. Check the cable from your home control box to your router, and that your internet works."
	r := newRig(t)
	r.hooks.mu.Lock()
	r.hooks.progress = Progress{Phase: "offline"}
	r.hooks.mu.Unlock()
	for _, path := range []string{"/setup", "/status"} {
		if page := r.get(path); !strings.Contains(page, step) {
			t.Fatalf("offline %s lacks the cable step: %s", path, page)
		}
	}
	r = newRig(t)
	r.runSetupToAI()
	r.hooks.mu.Lock()
	r.hooks.progress = Progress{Phase: "offline"}
	r.hooks.mu.Unlock()
	if page := r.get("/setup"); strings.Count(page, step) != 1 {
		t.Fatalf("offline AI step should name the cable step once: %s", page)
	}
	for _, phase := range []string{"booting", "updating", "ready"} {
		r.hooks.mu.Lock()
		r.hooks.progress = Progress{Phase: phase, Online: true}
		r.hooks.mu.Unlock()
		for _, path := range []string{"/setup", "/status"} {
			if strings.Contains(r.get(path), "cable") {
				t.Fatalf("%s %s mentions the cable", phase, path)
			}
		}
	}
}
