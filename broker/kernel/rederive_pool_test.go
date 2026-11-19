package kernel_test

// REQ: RES-5, LOG-7

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// A pool window's reset is a decision the log's replay derives again: the
// window read closed, then its reset time passed, so Rederive reproduces
// the reset the kernel logged and counts it checked, not recorded.
func TestPoolResetRederives(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 100))
	must(t, r.k.ReadPool(2, "p", []kernel.WindowReading{{Window: "5h", Used: 950, ResetAt: 1_000}}))
	r.k.AdmitPool(1_000, "p")
	es := r.k.Log().Entries()
	if last := es[len(es)-1]; last.Type != kernel.TPoolReset {
		t.Fatalf("last entry %s, want the window's reset", last.Type)
	}
	got, err := kernel.Rederive(r.anchors(), r.head.pub, es)
	if err != nil || got.Checked[kernel.TPoolReset] != 1 {
		t.Fatalf("rederive: %v, checked %v, want the reset checked once", err, got.Checked)
	}
}
