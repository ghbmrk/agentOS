package recalltool

// REQ: CAP-3

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/recall"
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
	r.prov.SetLimits(Limits{Notes: 3, NotesAll: 4})
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
	// Reads: a lineage past the read cap makes no notes.
	r3 := newRig(t).fast()
	r3.prov.SetLimits(Limits{Reads: 1})
	r3.call("m", "root", "recall_search", map[string]any{"query": "shed", "scope": "owner"})
	if _, err := r3.call("m", "root", "recall_note", map[string]any{"key": "n", "text": "x"}); err == nil {
		t.Fatal("read cap")
	}
}

// durable is a rig whose index sits on a kept directory and a pinned clock,
// so the tests can reopen it and age tombstones.
type durable struct {
	*rig
	dir   *recall.MemDir
	clock time.Time
}

func (d *durable) open(t *testing.T) {
	t.Helper()
	k, _ := recall.NewKeyer(key())
	ix, err := recall.Open(d.dir, recall.WithKeyer(k), recall.WithLabeler(d.lab), recall.WithClock(func() time.Time { return d.clock }))
	if err != nil {
		t.Fatal(err)
	}
	ix.KeepTombstones((&Reach{Prov: d.prov}).Needed)
	d.ix = ix
	d.tl, _ = New(Config{Index: ix, Prov: d.prov, Label: d.lab.str, Burst: 1 << 20, Now: func() time.Time { return d.clock }})
}

func newDurable(t *testing.T) *durable {
	t.Helper()
	r := newRig(t)
	d := &durable{rig: r, dir: recall.NewMemDir(), clock: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	d.open(t)
	for _, it := range []recall.Item{
		{Source: recall.Source{Kind: "mail", Account: "owner@example.test", Ref: "<m1@x>"}, Text: "invoice from acme for the garden shed", Received: d.clock},
		{Source: recall.Source{Kind: "web", Ref: "https://shed.example.test/"}, Label: recall.Public, Text: "garden shed prices", Received: d.clock},
	} {
		if _, err := d.ix.Ingest(it); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func (d *durable) notes(t *testing.T, n int, prefix string) {
	t.Helper()
	for i := 0; i < n; i++ {
		d.call("m", "root", "recall_search", map[string]any{"query": "shed note", "scope": "owner", "limit": 100})
		if _, err := d.call("m", "root", "recall_note", map[string]any{"key": fmt.Sprintf("%s%d", prefix, i), "text": fmt.Sprintf("shed note %d", i)}); err != nil {
			t.Fatalf("note %s%d: %v", prefix, i, err)
		}
	}
}

func (d *durable) alive(key string) bool {
	_, ok := d.ix.Get(d.ix.SourceID("agent", "", "root/"+key))
	return ok
}

// B1: the owner deletes a source; once the tombstone prune policy has run,
// the lineage still makes no note derived from it, also after a reopen.
func TestAnchorTombstoneSurvivesPrune(t *testing.T) {
	d := newDurable(t)
	d.call("m", "root", "recall_search", map[string]any{"query": "invoice", "scope": "owner"})
	d.notes(t, 2, "a")
	if _, err := d.ix.Delete(d.ix.SourceID("mail", "owner@example.test", "<m1@x>")); err != nil {
		t.Fatal(err)
	}
	d.clock = d.clock.Add(40 * 24 * time.Hour)
	if _, err := d.ix.PruneTombstones(30 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		if _, err := d.call("m", "root", "recall_note", map[string]any{"key": fmt.Sprintf("after%d", pass), "text": "z"}); err == nil {
			t.Fatalf("pass %d: a note derived from a deleted source was accepted after the prune", pass)
		}
		d.open(t) // and again from disk
	}
}

// B2: the chain collapses at its length cap, so a long-lived lineage keeps
// making notes, and both the old and the new notes still cascade.
func TestChainCollapsesAndStillCascades(t *testing.T) {
	d := newDurable(t)
	d.prov.SetLimits(Limits{Anchors: 3})
	d.call("m", "root", "recall_search", map[string]any{"query": "invoice", "scope": "owner"})
	d.notes(t, 12, "n")
	if d.prov.chainLen["root"] > 3 {
		t.Fatalf("chain %d longer than its cap", d.prov.chainLen["root"])
	}
	for _, p := range []*Provenance{d.prov, reopen(t, d.rig), compacted(t, d.rig)} {
		if p.chainLen["root"] != d.prov.chainLen["root"] || p.anchor["root"] != d.prov.anchor["root"] {
			t.Fatalf("chain state lost: %d %d", p.chainLen["root"], d.prov.chainLen["root"])
		}
	}
	if _, err := d.ix.Delete(d.ix.SourceID("mail", "owner@example.test", "<m1@x>")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if d.alive(fmt.Sprintf("n%d", i)) {
			t.Fatalf("n%d survived the deletion of a source read before it", i)
		}
	}
}

// B3: a refused note writes nothing, and a note whose ingest fails leaves
// no key behind; the journal compacts from write().
func TestRefusedNotesLeaveNoTrace(t *testing.T) {
	d := newDurable(t)
	d.prov.SetLimits(Limits{Notes: 1})
	d.notes(t, 1, "k")
	before := d.prov.lines
	for i := 0; i < 50; i++ {
		if _, err := d.call("m", "root", "recall_note", map[string]any{"key": fmt.Sprintf("x%d", i), "text": "y"}); err == nil {
			t.Fatal("cap not enforced")
		}
	}
	if d.prov.lines != before {
		t.Fatalf("refused notes grew the journal: %d -> %d", before, d.prov.lines)
	}
	d2 := newDurable(t)
	d2.call("m", "root", "recall_search", map[string]any{"query": "invoice", "scope": "owner"})
	d2.ix.Delete(d2.ix.SourceID("mail", "owner@example.test", "<m1@x>"))
	if _, err := d2.call("m", "root", "recall_note", map[string]any{"key": "z", "text": "y"}); err == nil {
		t.Fatal("note from a deleted source accepted")
	}
	if _, _, _ = d2.prov.Size("root"); d2.prov.notes["root"]["z"] {
		t.Fatal("a failed note left its key")
	}
	d3 := newDurable(t)
	mail := d3.ix.SourceID("mail", "owner@example.test", "<m1@x>")
	for i := 0; i < 200; i++ {
		d3.prov.Given("root", []string{mail}, d3.clock)
		d3.prov.Forget("root", mail)
	}
	if d3.prov.lines > 100 {
		t.Fatalf("journal never compacts: %d lines", d3.prov.lines)
	}
}

// R2: a source deleted several anchors back, after the index is reopened
// from its segments and after the provenance journal compacts.
func TestCascadeAfterReopenAndCompaction(t *testing.T) {
	d := newDurable(t)
	d.call("m", "root", "recall_search", map[string]any{"query": "invoice", "scope": "owner"})
	d.notes(t, 5, "n") // several anchors after the read of the mail
	d.prov = compacted(t, d.rig)
	d.open(t)
	if _, err := d.ix.Delete(d.ix.SourceID("mail", "owner@example.test", "<m1@x>")); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if d.alive(fmt.Sprintf("n%d", i)) {
			t.Fatalf("n%d survived", i)
		}
	}
	if _, err := d.call("m", "root", "recall_note", map[string]any{"key": "after", "text": "z"}); err == nil {
		t.Fatal("note accepted after the source was deleted")
	}
}
