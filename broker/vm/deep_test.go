package vm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// REQ: RES-4, REV-1

// Security R4 on #166: a layer nested deeper than overlay.MaxDepth cannot
// be measured, so it is over the cap: the snapshot is refused with the
// disk-budget text the guest can act on, never taken as no use, and the
// machine keeps running; flattened, it snapshots again.
func TestATooDeepLayerIsOverTheCap(t *testing.T) {
	e := newEnv(t, 8192)
	e.open()
	e.create("m1", admission.Accepted, 100)
	deep := filepath.Join(strings.Repeat("a/", overlay.MaxDepth+1), "f")
	e.guestWrite("m1", deep, "x")
	_, err := e.m.Step(bg, "m1")
	if !errors.Is(err, ErrQuota) || !strings.Contains(err.Error(), "nest") {
		t.Fatalf("snapshot of a too-deep layer: %v", err)
	}
	if mc, _ := e.m.Get("m1"); mc.State != Running {
		t.Fatalf("machine %s after the refusal", mc.State)
	}
	must(t, os.RemoveAll(filepath.Join(e.cfg.StateDir, "machines", "m1", "disk", "upper", "a")))
	if _, err := e.m.Step(bg, "m1"); err != nil {
		t.Fatalf("snapshot once flattened: %v", err)
	}
}
