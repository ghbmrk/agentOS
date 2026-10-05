package loops

import (
	"context"
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
	// A late implicit acceptance (owner LateRelease) is refused too.
	if err := h.Harvest(Outcome{Intent: "draft-8", Action: Implicit, Input: []byte("procedures/mail"), Output: []byte("v1")}); !errors.Is(err, ErrForgotten) {
		t.Fatalf("late implicit acceptance of an erased intent: %v", err)
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

// Security F1 on #153 (CAP-3): recall's deletion reach, through the
// harvester's ForgetIntents, also drops every candidate Loop 1 keeps whose
// brief carried an erased intent, as an
// evidence intent or as a dev case's task, so the next offer builds
// afresh; other kept candidates stay.
func TestErasedIntentsDropKeptCandidates(t *testing.T) {
	l, _, b, _ := newKeepRig(t)
	ctx := context.Background()
	h1, h2, h3 := hyp("k1", "task-a", "task-b"), hyp("k2", "task-c"), hyp("k3", "task-d")
	dev := Evidence{Dev: []change.Case{{ID: "d1", Task: "task-z"}}}
	l.propose(ctx, h1, Evidence{})
	l.propose(ctx, h2, dev)
	l.propose(ctx, h3, Evidence{})
	l.cfg.Harvest.Store = &change.MemStore{}
	must(t, l.cfg.Harvest.ForgetIntents([]string{"task-b", "task-z"}))
	l.mu.Lock()
	_, k1 := l.built["k1"]
	_, k2 := l.built["k2"]
	_, k3 := l.built["k3"]
	l.mu.Unlock()
	if k1 || k2 || !k3 {
		t.Fatalf("kept after the erase: k1 %v, k2 %v, k3 %v", k1, k2, k3)
	}
	l.propose(ctx, h1, Evidence{})
	l.propose(ctx, h3, Evidence{})
	if n := len(b.got()); n != 4 {
		t.Fatalf("%d builds, want 4: only the erased brief builds afresh", n)
	}
	// The reach's second call, after the journal erase, drops one kept
	// in between, though the harvester has nothing left to change.
	must(t, l.cfg.Harvest.ForgetIntents([]string{"task-b", "task-z"}))
	l.mu.Lock()
	_, k1 = l.built["k1"]
	l.mu.Unlock()
	if k1 {
		t.Fatal("a candidate kept between the reach's two calls stayed")
	}
}
