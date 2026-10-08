package guest

// REQ: RES-4, CAP-8

import (
	"strings"
	"testing"
)

// A tool name the guest chose reaches its error only when it is
// ID-shaped; a path does not (SR2-3k).
func TestAnUnknownToolNamedByAPathIsNotEchoed(t *testing.T) {
	r := newRig(t, nil)
	const canary = "/var/lib/agentos-canary-3k/state"
	_, errText := r.tool("fork-1", canary, nil)
	if !strings.Contains(errText, "no tool") || strings.Contains(errText, "canary") || strings.Contains(errText, "/") {
		t.Fatalf("guest saw %q", errText)
	}
	if _, errText := r.tool("fork-1", "nope", nil); !strings.Contains(errText, `"nope"`) {
		t.Fatalf("an ID-shaped name is not shown: %q", errText)
	}
}
