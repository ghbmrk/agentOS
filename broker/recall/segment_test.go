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

// appendFailDir fails appends after writing all of the data (a failed
// fsync) or half of it (a partial write), and rewrites while rewriteFail.
type appendFailDir struct {
	*MemDir
	appendFail, partial, rewriteFail bool
}

func (f *appendFailDir) Append(n uint32, data []byte) (int64, error) {
	if !f.appendFail {
		return f.MemDir.Append(n, data)
	}
	if f.partial {
		data = data[:len(data)/2]
	}
	f.MemDir.Append(n, data)
	return 0, errors.New("fsync failed")
}

func (f *appendFailDir) Rewrite(n uint32, data []byte) error {
	if f.rewriteFail {
		return errors.New("disk full")
	}
	return f.MemDir.Rewrite(n, data)
}

// A failed append leaves nothing memory does not know in a live segment,
// so the item can neither come back on reopen nor outlive its deletion,
// even after the tombstone is pruned (CAP-3, review of #51). If cutting
// the segment back fails too, the segment stays marked for erase and
// tombstones are not pruned until it is erased.
func TestFailedAppendLeavesNothingBehind(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		partial, cutBackFail bool
	}{{"fsync", false, false}, {"partial", true, false}, {"fsync, cut back fails", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
			st := &appendFailDir{MemDir: NewMemDir()}
			ix := open(t, st, WithKeyer(testKeyer(t)), WithClock(func() time.Time { return now }))
			mustIngest(t, ix, Item{Source: Source{Kind: "file", Ref: "/keep"}, Text: "kept item"})
			st.appendFail, st.partial, st.rewriteFail = true, tc.partial, tc.cutBackFail
			src := Source{Kind: "mail", Ref: "<z@x>"}
			if _, err := ix.Ingest(Item{Source: src, Text: "zebracanary synthetic"}); err == nil {
				t.Fatal("failed append reported success")
			}
			st.appendFail = false
			if _, err := ix.DeleteSource("mail", "", "<z@x>"); err != nil && !tc.cutBackFail {
				t.Fatal(err)
			}
			now = now.Add(40 * 24 * time.Hour)
			if tc.cutBackFail {
				if _, err := ix.PruneTombstones(30 * 24 * time.Hour); err == nil {
					t.Fatal("tombstones pruned while a segment holds unerased content")
				}
				st.rewriteFail = false
			}
			if _, err := ix.PruneTombstones(30 * 24 * time.Hour); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(st.Bytes()), "zebracanary") {
				t.Fatal("content of a failed append remains on the medium")
			}
			re := open(t, st, WithKeyer(testKeyer(t)))
			if rs := re.Lookup(Query{Text: "zebracanary"}); len(rs) != 0 || re.Len() != 1 {
				t.Fatalf("after reopen: %d results, %d items", len(rs), re.Len())
			}
			// Ingest works again afterwards.
			mustIngest(t, re, Item{Source: Source{Kind: "file", Ref: "/after"}, Text: "after"})
		})
	}
}

// An item whose stored line cannot be read is still deleted: tombstone
// written, bytes erased, nothing returned for it (CAP-3, review of #51).
func TestUnreadableItemIsStillDeleted(t *testing.T) {
	path := t.TempDir()
	st, err := OpenDir(path)
	if err != nil {
		t.Fatal(err)
	}
	ix := open(t, st, WithKeyer(testKeyer(t)))
	id := mustIngest(t, ix, Item{Source: Source{Kind: "mail", Ref: "<c@x>"}, Text: "yakcanary synthetic"})
	mustIngest(t, ix, Item{Source: Source{Kind: "file", Ref: "/keep"}, Text: "kept item"})
	segs, _ := st.Segments()
	data, err := st.ReadSegment(segs[0])
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(data), "yakcanary")
	data[i-2] = 0 // break the line's JSON just before the text
	if err := st.Rewrite(segs[0], data); err != nil {
		t.Fatal(err)
	}
	if _, err := ix.Delete(id); err != nil {
		t.Fatalf("delete of an unreadable item: %v", err)
	}
	if _, ok := ix.Get(id); ok {
		t.Fatal("item still present")
	}
	if strings.Contains(string(readDir(t, path)), "yakcanary") {
		t.Fatal("bytes of the deleted item remain")
	}
	if ix.Len() != 1 {
		t.Fatalf("other items: %d", ix.Len())
	}
}

// A batch that spans segments and fails part-way reports the items written
// before the failure as ingested and only the rest as failed (review of
// #51, round 2).
func TestIngestBatchReportsPartialFailure(t *testing.T) {
	smallSegments(t, 4)
	st := &appendFailAfter{MemDir: NewMemDir(), okAppends: 1}
	ix := open(t, st, WithKeyer(testKeyer(t)))
	var items []Item
	for i := 0; i < 8; i++ {
		items = append(items, Item{Source: Source{Kind: "file", Ref: fmt.Sprint("/b", i)}, Text: fmt.Sprint("batch item ", i)})
	}
	ids, errs := ix.IngestBatch(items)
	for i := range items {
		_, present := ix.Get(ix.SourceID("file", "", fmt.Sprint("/b", i)))
		ok := errs[i] == nil && ids[i] != ""
		if ok != present {
			t.Errorf("item %d: reported ok=%v (id %q, err %v) but present=%v", i, ok, ids[i], errs[i], present)
		}
	}
	if errs[0] != nil || errs[7] == nil {
		t.Fatalf("want the first segment written and the second failed: %v", errs)
	}
}

// appendFailAfter lets okAppends appends through, then fails every one
// after writing it (a failed fsync).
type appendFailAfter struct {
	*MemDir
	okAppends int
}

func (f *appendFailAfter) Append(n uint32, data []byte) (int64, error) {
	if f.okAppends > 0 {
		f.okAppends--
		return f.MemDir.Append(n, data)
	}
	f.MemDir.Append(n, data)
	return 0, errors.New("fsync failed")
}
