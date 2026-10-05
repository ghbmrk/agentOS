package loops

import (
	"fmt"
	"strings"
	"testing"
)

// REQ: CAP-3, CHG-1

// W3-tasks part 1 (L3 on #123): forgetting a task's cases also drops the
// harvester's records of them, so the held-out evidence no longer counts
// cases the suite has lost, and harvest.json keeps none of their IDs.
func TestHarvesterForgetsCases(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	for i := range 8 {
		r.corrected(h, i)
	}
	before, err := h.Evidence()
	must(t, err)
	var gone []string
	for i := range 8 {
		if id := fmt.Sprintf("draft-%d", i); before.heldIntents[id] {
			gone = append(gone, id)
			break
		}
	}
	if len(gone) == 0 {
		t.Fatal("no held-out case to forget")
	}
	must(t, h.ForgetCases(gone))
	after, err := h.Evidence()
	must(t, err)
	if after.HeldOut != before.HeldOut-1 {
		t.Fatalf("held out %d, was %d: a forgotten case still counts", after.HeldOut, before.HeldOut)
	}
	raw, err := h.Store.Load()
	must(t, err)
	for _, id := range gone {
		if strings.Contains(string(raw), `"`+id+`"`) {
			t.Fatalf("harvest state still names %s: %s", id, raw)
		}
	}
}
