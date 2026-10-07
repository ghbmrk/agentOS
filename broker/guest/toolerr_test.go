package guest

import (
	"strings"
	"testing"
)

// REQ: RES-4, CAP-8
func TestSR23gHostPathBecomesRef(t *testing.T) {
	canary := "open /tmp/canary-host-path-7f3a: permission denied"
	got := guestFacingErr("effect_request", canary)
	if strings.Contains(got, "/tmp/") || strings.Contains(got, "canary") {
		t.Fatalf("leaked host path: %q", got)
	}
	if !strings.Contains(got, "ref ") {
		t.Fatalf("want ref, got %q", got)
	}
}

// REQ: RES-4
func TestSR23gAllowlistedReasonPasses(t *testing.T) {
	fixed := "no adapter is connected for that account"
	if got := guestFacingErr("effect_request", fixed); got != fixed {
		t.Fatalf("got %q", got)
	}
}

// REQ: CAP-8
func TestSR23gWindowsPathScrubbed(t *testing.T) {
	got := guestFacingErr("worker_exec", `read C:\Users\owner\secret.txt`)
	if strings.Contains(got, `C:`) || strings.Contains(got, "secret") {
		t.Fatalf("leaked: %q", got)
	}
}
