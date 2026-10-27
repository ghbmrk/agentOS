package localui

import (
	"strings"
	"testing"
)

// REQ: ONB-4, CH-12
// WIFI-del-offline-note (#3327): the core's only uplink is its cable to
// the enforcer (HW-12, D-178), so an offline core names that one step on
// every page that says it is offline, from the first setup step on.
func TestOfflineNamesTheCableToTheEnforcer(t *testing.T) {
	const step = "Check the cable from my port 1 to your home control box."
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
		if strings.Contains(r.get("/setup"), "cable") {
			t.Fatalf("%s page mentions the cable", phase)
		}
	}
}
