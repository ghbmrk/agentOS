package recall

// Segmented store (R8): deletion erases every version from every segment,
// survives a failed or interrupted erase, and batches ingest like Ingest.
// REQ: CAP-3

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func smallSegments(t *testing.T, lines int) {
	t.Helper()
	ol, ob := segMaxLines, segMaxBytes
	segMaxLines, segMaxBytes = lines, 1<<20
	t.Cleanup(func() { segMaxLines, segMaxBytes = ol, ob })
}

// A deletion erases the item's current version and every superseded one,
// whichever segments hold them, and rewrites only those segments.
func TestDeleteErasesEveryVersionInEverySegment(t *testing.T) {
	smallSegments(t, 4)
	st := NewMemDir()
	ix := open(t, st, WithKeyer(testKeyer(t)))
	mustIngest(t, ix, Item{Source: Source{Kind: "mail", Ref: "<v@x>"}, Text: "first version quokkaone"})
	for i := 0; i < 9; i++ {
		mustIngest(t, ix, Item{Source: Source{Kind: "file", Ref: fmt.Sprint("/f", i)}, Text: "filler"})
	}
	id := mustIngest(t, ix, Item{Source: Source{Kind: "mail", Ref: "<v@x>"}, Text: "second version quokkatwo"})
	if segs, _ := st.Segments(); len(segs) < 3 {
		t.Fatalf("want several segments, got %v", segs)
	}
	before := map[uint32][]byte{}
	segs, _ := st.Segments()
	for _, n := range segs {
		before[n], _ = st.ReadSegment(n)
	}
	if _, err := ix.Delete(id); err != nil {
		t.Fatal(err)
	}
	if b := string(st.Bytes()); strings.Contains(b, "quokka") {
		t.Fatal("a version of the deleted item remains on the medium")
	}
	// Segments that never held it are untouched.
	untouched := 0
	for n, b := range before {
		if strings.Contains(string(b), "quokka") {
			continue
		}
		after, _ := st.ReadSegment(n)
		if string(after) != string(b) {
			t.Fatalf("segment %d rewritten though it never held the item", n)
		}
		untouched++
	}
	if untouched == 0 {
		t.Fatal("test needs a segment without the item")
	}
	re := open(t, st, WithKeyer(testKeyer(t)))
	if re.Len() != 9 {
		t.Fatalf("after reopen: %d items", re.Len())
	}
}

// failingDir fails segment rewrites while fail is set.
type failingDir struct {
	*MemDir
	fail bool
}

func (f *failingDir) Rewrite(n uint32, data []byte) error {
	if f.fail {
		return errors.New("disk full")
	}
	return f.MemDir.Rewrite(n, data)
}

// Once its tombstone is durable a deletion has taken effect: a failed erase
// is reported, the item is gone from memory, the erase is retried, and a
// restart erases what is left (a crash between the two steps alike).
func TestDeletionDurableBeforeErase(t *testing.T) {
	d := &failingDir{MemDir: NewMemDir()}
	ix := open(t, d, WithKeyer(testKeyer(t)))
	var hooked int
	ix.OnDelete(func(Deleted) error { hooked++; return nil })
	id := mustIngest(t, ix, Item{Source: Source{Kind: "mail", Ref: "<e@x>"}, Text: "wombatsecret"})
	keep := mustIngest(t, ix, Item{Source: Source{Kind: "file", Ref: "/k"}, Text: "kept"})
	d.fail = true
	if _, err := ix.Delete(id); err == nil {
		t.Fatal("a failed erase must be reported")
	}
	if _, ok := ix.Get(id); ok || hooked != 1 {
		t.Fatalf("deletion must hold and propagate: present=%v hooks=%d", ok, hooked)
	}
	if rs := ix.Lookup(Query{Text: "wombatsecret"}); len(rs) != 0 {
		t.Fatal("deleted item still searchable")
	}
	if _, err := ix.PruneTombstones(30 * 24 * time.Hour); err == nil {
		t.Fatal("tombstones pruned while their content waits to be erased")
	}
	// A restart (with the medium working again) erases it.
	d.fail = false
	re := open(t, d, WithKeyer(testKeyer(t)))
	if strings.Contains(string(d.Bytes()), "wombatsecret") {
		t.Fatal("restart did not erase the deleted content")
	}
	if _, ok := re.Get(keep); !ok || re.Len() != 1 {
		t.Fatal("unrelated item lost")
	}
	// Or the next deletion retries it.
	d2 := &failingDir{MemDir: NewMemDir()}
	ix2 := open(t, d2, WithKeyer(testKeyer(t)))
	a := mustIngest(t, ix2, Item{Source: Source{Kind: "mail", Ref: "<a@x>"}, Text: "platypusone"})
	d2.fail = true
	ix2.Delete(a)
	d2.fail = false
	if _, err := ix2.DeleteSource("mail", "", "<other@x>"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(d2.Bytes()), "platypusone") {
		t.Fatal("the next deletion did not retry the erase")
	}
}

// Batch ingest admits each item exactly as Ingest would.
func TestIngestBatchMatchesIngest(t *testing.T) {
	smallSegments(t, 3)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	ix := open(t, NewMemDir(), WithKeyer(testKeyer(t)), WithClock(func() time.Time { return now }))
	gone := ix.SourceID("mail", "", "<gone@x>")
	ix.Delete(gone)
	parent := ix.SourceID("web", "", "https://p.example.test/")
	ids, errs := ix.IngestBatch([]Item{
		{Source: Source{Kind: "web", Ref: "https://p.example.test/"}, Label: Public, Received: now, Text: "public page"},
		{Source: Source{Kind: "agent", Ref: "sum", DerivedFrom: []string{parent}}, Label: Public, Received: now, Text: "summary of page"},
		{Source: Source{Kind: "mail", Ref: "<gone@x>"}, Received: now.Add(-time.Minute), Text: "stale"},
		{Source: Source{Kind: "mail", Ref: "<m@x>"}, Received: now, Text: "first"},
		{Source: Source{Kind: "web", Ref: "https://q.example.test/"}, Received: now, Text: "declared private"},
		{Source: Source{Kind: "web", Ref: "https://q.example.test/"}, Label: Public, Received: now, Text: "now declared public"},
		{Source: Source{Kind: "mail", Ref: "<m@x>"}, Received: now, Text: "second"},
		{Source: Source{Kind: "mail"}, Text: "no ref"},
	})
	if !errors.Is(errs[2], ErrDeleted) || !errors.Is(errs[7], ErrNoSource) {
		t.Fatalf("refusals: %v", errs)
	}
	for _, i := range []int{0, 1, 3, 4, 5, 6} {
		if errs[i] != nil || ids[i] == "" {
			t.Fatalf("item %d: %q %v", i, ids[i], errs[i])
		}
	}
	// The parent earlier in the batch counts: the summary stays public.
	if it, _ := ix.Get(ids[1]); it.Label != Public {
		t.Fatalf("derived from a public parent in the same batch: %s", it.Label)
	}
	// A label never falls within a batch either.
	if it, _ := ix.Get(ids[5]); it.Label != Private || it.Text != "now declared public" {
		t.Fatalf("label fell within a batch: %+v", it)
	}
	if it, _ := ix.Get(ids[6]); it.Text != "second" || ix.Len() != 4 {
		t.Fatalf("last version wins: %q, %d items", it.Text, ix.Len())
	}
}

// Superseded versions are compacted away once they dominate a segment.
func TestSupersededVersionsCompacted(t *testing.T) {
	smallSegments(t, 100)
	st := NewMemDir()
	ix := open(t, st, WithKeyer(testKeyer(t)))
	for round := 0; round < 3; round++ {
		for i := 0; i < 100; i++ {
			mustIngest(t, ix, Item{Source: Source{Kind: "file", Ref: fmt.Sprint("/f", i)}, Text: fmt.Sprint("round ", round)})
		}
	}
	segs, _ := st.Segments()
	total := 0
	for _, n := range segs {
		b, _ := st.ReadSegment(n)
		total += strings.Count(string(b), "\n")
	}
	if total > 200 {
		t.Fatalf("%d lines kept for 100 items in %d segments", total, len(segs))
	}
	if rs := ix.Lookup(Query{Text: "round", Limit: 100}); len(rs) != 100 || rs[0].Text != "round 2" {
		t.Fatalf("after compaction: %d results", len(rs))
	}
}
