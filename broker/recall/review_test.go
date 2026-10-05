package recall

// Tests for the #38 review fix-list.
// REQ: CAP-3, REV-5

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A public-only search must not depend on private items in any way: not in
// which results come back, nor in their order (review item 1).
func TestPublicOnlySearchIgnoresPrivateStatistics(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	// a and b tie on public statistics (a wins the tie as the newer item);
	// private "acme" mails would lower acme's IDF and flip them.
	pubItems := []Item{
		{Source: Source{Kind: "web", Ref: "a", Seen: t0.Add(time.Hour)}, Label: Public, Text: "acme alpha beta"},
		{Source: Source{Kind: "web", Ref: "b", Seen: t0}, Label: Public, Text: "widgets alpha beta"},
		{Source: Source{Kind: "web", Ref: "c", Seen: t0}, Label: Public, Text: "garden widgets gamma"},
	}
	run := func(privates int) string {
		var out []string
		for _, emb := range []Embedder{nil, HashEmbedder{}} {
			ix := open(t, &MemStore{}, WithKeyer(testKeyer(t)), WithEmbedder(emb))
			for _, it := range pubItems {
				mustIngest(t, ix, it)
			}
			for i := 0; i < privates; i++ {
				mustIngest(t, ix, Item{Source: Source{Kind: "mail", Ref: fmt.Sprint("m", i)}, Text: "acme acme invoice"})
			}
			for _, q := range []string{"acme widgets", "widgets", "acme"} {
				for limit := 1; limit <= 3; limit++ {
					rs, err := ix.Search("pub", Query{Text: q, PublicOnly: true, Limit: limit})
					if err != nil {
						t.Fatal(err)
					}
					for _, r := range rs {
						out = append(out, r.Source.Ref)
					}
					out = append(out, "|")
				}
			}
		}
		return strings.Join(out, ",")
	}
	base := run(0)
	for _, n := range []int{1, 5, 50} {
		if got := run(n); got != base {
			t.Fatalf("public-only results changed with %d private items:\n%s\n%s", n, base, got)
		}
	}
}

func testKeyer(t *testing.T) Keyer {
	t.Helper()
	k, err := NewKeyer([]byte("synthetic-test-key-0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Identity uses the raw ref, keyed, so refs that scrub alike stay distinct
// and deletion by raw ref works (review item 3).
func TestIdentityFromRawRef(t *testing.T) {
	ix := open(t, &MemStore{})
	r1 := "https://site.example.test/doc?token=Zq8XkP3vLm2RtY7wNb4C"
	r2 := "https://site.example.test/doc?token=Hd5JsQ9aWe1UoI6pVc3T"
	a := mustIngest(t, ix, Item{Source: Source{Kind: "web", Ref: r1}, Text: "first"})
	b := mustIngest(t, ix, Item{Source: Source{Kind: "web", Ref: r2}, Text: "second"})
	if a == b || ix.Len() != 2 {
		t.Fatal("refs that scrub alike collided")
	}
	if it, _ := ix.Get(a); strings.Contains(it.Source.Ref, "Zq8XkP3v") {
		t.Fatal("displayed ref not scrubbed")
	}
	rep, err := ix.DeleteSource("web", "", r1)
	if err != nil || len(rep.Items) != 1 || rep.Items[0] != a {
		t.Fatalf("delete by raw ref: %v %+v", err, rep)
	}
	if _, err := NewKeyer([]byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}

// The identity key survives a restart (generated key kept in the header).
func TestGeneratedKeyPersists(t *testing.T) {
	st := &MemStore{}
	ix := open(t, st)
	id := mustIngest(t, ix, Item{Source: Source{Kind: "file", Ref: "/a"}, Text: "x"})
	re := open(t, st)
	if re.SourceID("file", "", "/a") != id {
		t.Fatal("identity changed across restart")
	}
}

// A deletion that arrives before the item is indexed still reaches hooks,
// and stale content seen before the deletion is refused (items 4 and 5).
func TestDeletionBeforeIndexingAndTombstones(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	st := &MemStore{}
	ix := open(t, st, WithClock(clock))
	var hooked []Deleted
	ix.OnDelete(func(d Deleted) error { hooked = append(hooked, d); return nil })
	id := ix.SourceID("mail", "o", "<late@x>")
	if _, err := ix.DeleteSource("mail", "o", "<late@x>"); err != nil {
		t.Fatal(err)
	}
	if len(hooked) != 1 || hooked[0].ID != id {
		t.Fatalf("hooks not run for an unindexed deletion: %+v", hooked)
	}
	// A stale delivery of the deleted mail is refused.
	if _, err := ix.Ingest(Item{Source: Source{Kind: "mail", Account: "o", Ref: "<late@x>", Seen: now.Add(-time.Hour)}, Text: "old"}); !errors.Is(err, ErrDeleted) {
		t.Fatalf("stale ingest after delete: %v", err)
	}
	// New content at the same source after the deletion is accepted.
	now = now.Add(time.Minute)
	if _, err := ix.Ingest(Item{Source: Source{Kind: "mail", Account: "o", Ref: "<late@x>"}, Text: "new"}); err != nil {
		t.Fatalf("new content after delete: %v", err)
	}
	// Tombstones are durable and replayed to hooks registered later, so a
	// deletion cut off by a crash still propagates.
	re := open(t, st, WithClock(clock))
	var replayed []Deleted
	if err := re.OnDelete(func(d Deleted) error { replayed = append(replayed, d); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(replayed) != 1 || replayed[0].ID != id {
		t.Fatalf("tombstone not replayed: %+v", replayed)
	}
	// Hook errors are reported after the deletion is durable.
	bad := open(t, &MemStore{})
	bad.OnDelete(func(Deleted) error { return errors.New("bus store full") })
	x := mustIngest(t, bad, Item{Source: Source{Kind: "file", Ref: "/x"}, Text: "x"})
	if _, err := bad.Delete(x); err == nil {
		t.Fatal("hook error swallowed")
	}
	if _, ok := bad.Get(x); ok {
		t.Fatal("deletion must hold even when a hook fails")
	}
}

type otherEmbedder struct{}

func (otherEmbedder) ID() string { return "other-model/3" }
func (otherEmbedder) Embed(ts []string) ([][]float32, error) {
	out := make([][]float32, len(ts))
	for i := range ts {
		out[i] = []float32{1, 0, 0}
	}
	return out, nil
}

// Vectors carry their embedder's identity; vectors from another space are
// ignored until re-embedded (review item 7).
func TestEmbedderIdentity(t *testing.T) {
	st := &MemStore{}
	ix := open(t, st)
	id := mustIngest(t, ix, Item{Source: Source{Kind: "file", Ref: "/a"}, Text: "Quarterly invoicing summary"})
	if it, _ := ix.Get(id); it.VecID != (HashEmbedder{}).ID() {
		t.Fatalf("vector id: %q", it.VecID)
	}
	// Reopened with another embedder: the old vectors are not compared with
	// the new space (otherEmbedder would match everything), so only text
	// matches count.
	re := open(t, st, WithEmbedder(otherEmbedder{}))
	if rs := re.Lookup(Query{Text: "garden"}); len(rs) != 0 {
		t.Fatalf("cross-space vectors compared: %+v", rs)
	}
	if rs := re.Lookup(Query{Text: "invoicing"}); len(rs) != 1 {
		t.Fatalf("text must still answer: %+v", rs)
	}
	n, err := re.Reembed(10)
	if err != nil || n != 1 {
		t.Fatalf("reembed: %d %v", n, err)
	}
	if it, _ := re.Get(id); it.VecID != "other-model/3" {
		t.Fatal("not re-embedded")
	}
	data, _ := st.ReadAll()
	if !strings.Contains(string(data), `"embedder":"other-model/3"`) {
		t.Fatal("store header does not name the embedder")
	}
}

func TestCorruptMiddleLineSkipped(t *testing.T) {
	st := &MemStore{}
	ix := open(t, st)
	mustIngest(t, ix, Item{Source: Source{Kind: "file", Ref: "/a"}, Text: "alpha"})
	st.Append([]byte("{not json\n"))
	ix2 := open(t, st)
	mustIngest(t, ix2, Item{Source: Source{Kind: "file", Ref: "/b"}, Text: "beta"})
	re := open(t, st)
	if re.Len() != 2 {
		t.Fatalf("items: %d", re.Len())
	}
	if ix2.Skipped() != 1 {
		t.Fatalf("skipped: %d", ix2.Skipped())
	}
}

func TestExistingStoreTightened(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.jsonl")
	os.WriteFile(path, nil, 0o644)
	st, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestPublicIdentifiersKept(t *testing.T) {
	sc := NewScrubber(nil)
	in := "Your parcel 1Z999AA10123456784 ships today; ticket 0012345678901"
	if out := sc.Scrub(in); out != in {
		t.Fatalf("over-scrubbed: %q", out)
	}
}
