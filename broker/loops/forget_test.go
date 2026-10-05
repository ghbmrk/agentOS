package loops

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
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

// Recall's deletion reach (security F1 on #59, change C19): an erased
// intent is never harvested, not even one still in flight that settles
// and gets the owner's verdict after the reset; one already harvested
// stops counting as evidence but its task stays held from mining; and
// forgetting again changes nothing.
func TestHarvesterRefusesErasedIntents(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	for i := range 8 {
		r.corrected(h, i)
	}
	before, err := h.Evidence()
	must(t, err)
	held := ""
	for i := range 8 {
		if id := fmt.Sprintf("draft-%d", i); before.heldIntents[id] {
			held = id
			break
		}
	}
	if held == "" {
		t.Fatal("no held-out case")
	}
	// draft-8 is in flight when the reach runs; it settles afterwards.
	r.task("draft-8", "g8", "mail", "draft", "private")
	gone := []string{held, "draft-8"}
	must(t, h.ForgetIntents(gone))
	_, err = r.p.ForgetTasks(gone...)
	must(t, err)
	must(t, h.ForgetIntents(gone))
	err = h.Harvest(Outcome{Intent: "draft-8", Action: Edited, Input: []byte("procedures/mail"), Output: []byte("v1"), Correction: []byte("v2")})
	if !errors.Is(err, ErrForgotten) {
		t.Fatalf("harvest of an erased intent: %v", err)
	}
	if st, _ := r.eng.Get("draft-8"); st.Quality.Verdict != "" {
		t.Fatalf("verdict recorded on an erased intent: %+v", st.Quality)
	}
	after, err := h.Evidence()
	must(t, err)
	if after.HeldOut != before.HeldOut-1 || !after.heldIntents[held] {
		t.Fatalf("held out %d (was %d), still held %v", after.HeldOut, before.HeldOut, after.heldIntents[held])
	}
	for _, c := range r.p.Dev(change.ClassTask) {
		if c.ID == held || c.ID == "draft-8" {
			t.Fatalf("pipeline still holds %s", c.ID)
		}
	}
}
