package update

import (
	"strings"
	"testing"
)

// REQ: UPD-3, UPD-b

func TestUPDbFirstBootHoldsAIUntilStable(t *testing.T) {
	f := FirstBoot{StableActive: false, Online: true}
	if !f.HoldConnect() {
		t.Fatal("should hold")
	}
	line := f.StatusLine()
	if !strings.Contains(line, "Updating first") || !strings.Contains(line, "AI") {
		t.Fatalf("status: %q", line)
	}
	f.Online, f.Preloaded = false, true
	line = f.StatusLine()
	if !strings.Contains(line, "preloaded") || !strings.Contains(line, "offline") {
		t.Fatalf("offline: %q", line)
	}
	f.StableActive = true
	if f.HoldConnect() || f.StatusLine() != "" {
		t.Fatal("stable should release hold")
	}
}
