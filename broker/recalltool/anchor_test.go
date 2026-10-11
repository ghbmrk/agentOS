package recalltool

// REQ: CAP-3

import (
	"fmt"
	"strings"
	"testing"
)

// derivedTotal counts the DerivedFrom entries the index holds for lineage
// notes and anchors: the memory and disk a guest makes the broker keep.
// fast lifts the per-machine rate limit, which is not under test here.
func (r *rig) fast() *rig {
	r.tl, _ = New(Config{Index: r.ix, Prov: r.prov, Label: r.lab.str, Burst: 1 << 20})
	return r
}

func (r *rig) derivedTotal(lineage string, notes int) int {
	n := 0
	for i := 0; i < notes; i++ {
		if it, ok := r.ix.Get(r.ix.SourceID("agent", "", fmt.Sprintf("%s/n%d", lineage, i))); ok {
			n += len(it.Source.DerivedFrom)
		}
	}
	for i := 1; i <= r.prov.anchors[lineage]; i++ {
		if it, ok := r.ix.Get(r.ix.SourceID("agent", "", fmt.Sprintf("%s/_anchor/%d", lineage, i))); ok {
			n += len(it.Source.DerivedFrom)
		}
	}
	return n
}

// A note carries one source, whatever the lineage has read, and the total
// the broker keeps grows linearly with notes: the guest's own notes come
// back in its searches, which used to make each note copy all before it.
func TestNoteProvenanceGrowsLinearly(t *testing.T) {
	sizes := map[int]int{}
	for _, n := range []int{20, 40} {
		r := newRig(t).fast()
		for i := 0; i < n; i++ {
			r.call("m", "root", "recall_search", map[string]any{"query": "shed note", "scope": "owner", "limit": 100})
			if _, err := r.call("m", "root", "recall_note", map[string]any{"key": fmt.Sprintf("n%d", i), "text": fmt.Sprintf("shed note %d", i)}); err != nil {
				t.Fatal(err)
			}
			it, ok := r.ix.Get(r.ix.SourceID("agent", "", fmt.Sprintf("root/n%d", i)))
			if !ok || len(it.Source.DerivedFrom) != 1 {
				t.Fatalf("note %d: %+v", i, it.Source.DerivedFrom)
			}
		}
		sizes[n] = r.derivedTotal("root", n)
		if reads, _, _ := r.prov.Size("root"); reads < n {
			t.Fatalf("notes were not read back: %d reads", reads)
		}
	}
	// Linear: doubling the notes at most doubles (plus a constant) the total.
	if sizes[40] > 2*sizes[20]+4 {
		t.Fatalf("provenance grows faster than linearly: %v", sizes)
	}
}

// Anchors are not content: no search finds one.
func TestAnchorsAreNotSearchable(t *testing.T) {
	r := newRig(t).fast()
	r.call("m", "root", "recall_search", map[string]any{"query": "shed", "scope": "owner"})
	r.call("m", "root", "recall_note", map[string]any{"key": "a", "text": "shed"})
	for _, q := range []string{"anchor", "_anchor", "root", "agent", "shed"} {
		out, _ := r.call("m", "root", "recall_search", map[string]any{"query": q, "scope": "owner", "kinds": []string{"agent"}})
		if strings.Contains(out, "_anchor") {
			t.Fatalf("anchor found by %q: %s", q, out)
		}
	}
}

// Deleting a source deletes the notes made after it was read, through the
// anchor chain, and only those; a note made before the read stays.
func TestDeletionCascadesThroughAnchors(t *testing.T) {
	r := newRig(t).fast()
	r.call("m", "root", "recall_search", map[string]any{"query": "garden", "scope": "public"}) // the web page
	r.call("m", "root", "recall_note", map[string]any{"key": "early", "text": "x"})
	r.call("m", "root", "recall_search", map[string]any{"query": "invoice", "scope": "owner"}) // the mail
	mail := r.ix.SourceID("mail", "owner@example.test", "<m1@x>")
	for i := 0; i < 5; i++ {
		r.call("m", "root", "recall_note", map[string]any{"key": fmt.Sprintf("late%d", i), "text": "y"})
		r.call("m", "root", "recall_search", map[string]any{"query": "shed", "scope": "owner"})
	}
	if _, err := r.ix.Delete(mail); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, ok := r.ix.Get(r.ix.SourceID("agent", "", fmt.Sprintf("root/late%d", i))); ok {
			t.Fatalf("late%d survived the deletion of a source it read", i)
		}
	}
	if _, ok := r.ix.Get(r.ix.SourceID("agent", "", "root/early")); !ok {
		t.Fatal("a note made before the read was deleted")
	}
	if _, err := r.call("m", "root", "recall_note", map[string]any{"key": "after", "text": "z"}); err == nil {
		t.Fatal("a note derived from the deleted mail was accepted")
	}
}

// What a lineage forgets (a take-back) leaves its chain: the next note
// derives from what is still held, and it all survives a reopen.
func TestForgetDropsTheChain(t *testing.T) {
	r := newRig(t).fast()
	r.call("m", "root", "recall_search", map[string]any{"query": "invoice", "scope": "owner"})
	r.call("m", "root", "recall_note", map[string]any{"key": "a", "text": "x"})
	mail := r.ix.SourceID("mail", "owner@example.test", "<m1@x>")
	if err := r.prov.Forget("root", mail); err != nil {
		t.Fatal(err)
	}
	r.call("m", "root", "recall_search", map[string]any{"query": "garden", "scope": "public"})
	if _, err := r.call("m", "root", "recall_note", map[string]any{"key": "b", "text": "y"}); err != nil {
		t.Fatal(err)
	}
	b, _ := r.ix.Get(r.ix.SourceID("agent", "", "root/b"))
	anc, ok := r.ix.Get(b.Source.DerivedFrom[0])
	if !ok {
		t.Fatal("no anchor")
	}
	for _, d := range anc.Source.DerivedFrom {
		if d == mail {
			t.Fatal("anchor still derives from a forgotten source")
		}
	}
	for _, again := range []*Provenance{reopen(t, r), compacted(t, r)} {
		if again.anchor["root"] != r.prov.anchor["root"] || again.anchors["root"] != r.prov.anchors["root"] || len(again.covered["root"]) != len(r.prov.covered["root"]) || len(again.notes["root"]) != 2 {
			t.Fatalf("anchor state lost: %v %v %v", again.anchor, again.anchors, again.notes)
		}
	}
}

func reopen(t *testing.T, r *rig) *Provenance {
	t.Helper()
	p, err := OpenProvenance(r.prst)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func compacted(t *testing.T, r *rig) *Provenance {
	t.Helper()
	p := reopen(t, r)
	if err := p.compact(); err != nil {
		t.Fatal(err)
	}
	return reopen(t, r)
}

// Caps are refused before the note is stored, with a plain error.
func TestNoteLimitsFailClosed(t *testing.T) {
	r := newRig(t).fast()
	r.prov.SetLimits(Limits{Notes: 3, NotesAll: 4, Anchors: 2, AnchorsAll: 100})
	note := func(l, k string) error {
		_, err := r.call("m-"+l, l, "recall_note", map[string]any{"key": k, "text": "x"})
		return err
	}
	for i := 0; i < 3; i++ {
		if err := note("a", fmt.Sprintf("k%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := note("a", "k0"); err != nil { // a replacement costs nothing
		t.Fatal(err)
	}
	before := r.ix.Len()
	if err := note("a", "k3"); err == nil || !strings.Contains(err.Error(), "allow") {
		t.Fatalf("per-lineage note cap: %v", err)
	}
	if r.ix.Len() != before {
		t.Fatal("a refused note was stored")
	}
	if err := note("b", "k0"); err != nil {
		t.Fatal(err)
	}
	if err := note("c", "k0"); err == nil {
		t.Fatal("global note cap")
	}
	// A deleted note frees its place.
	if _, err := r.ix.Delete(r.ix.SourceID("agent", "", "a/k1")); err != nil {
		t.Fatal(err)
	}
	if err := note("c", "k0"); err != nil {
		t.Fatalf("a deleted note should free a place: %v", err)
	}
	// Anchors: each note after new reads makes one, up to the cap.
	r2 := newRig(t).fast()
	r2.prov.SetLimits(Limits{Anchors: 2})
	var errs int
	for i := 0; i < 4; i++ {
		r2.call("m", "root", "recall_search", map[string]any{"query": "shed note", "scope": "owner", "limit": 100})
		if _, err := r2.call("m", "root", "recall_note", map[string]any{"key": fmt.Sprintf("n%d", i), "text": fmt.Sprintf("shed note %d", i)}); err != nil {
			errs++
		}
	}
	if _, _, an := r2.prov.Size("root"); an != 2 || errs == 0 {
		t.Fatalf("anchors %d, refused %d", an, errs)
	}
	// Reads: a lineage past the read cap makes no notes.
	r3 := newRig(t).fast()
	r3.prov.SetLimits(Limits{Reads: 1})
	r3.call("m", "root", "recall_search", map[string]any{"query": "shed", "scope": "owner"})
	if _, err := r3.call("m", "root", "recall_note", map[string]any{"key": "n", "text": "x"}); err == nil {
		t.Fatal("read cap")
	}
}
