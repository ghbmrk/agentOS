package retrieve

// REQ: LOG-4, LOG-1, PLN-7, PLN-3

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// fakeEmbed gives each text a fixed vector from a concept table: words
// of one concept share a dimension, and every other word adds a little
// to a dimension of its own. Its switches make it misbehave.
type fakeEmbed struct {
	mu                          sync.Mutex
	down, nan, inf, zero, extra bool
	model                       string
	dim                         int
	calls                       int
	maxTexts                    int
}

var concepts = map[string]int{
	"invoice": 0, "bill": 0, "payment": 0, "pay": 0, "owed": 0,
	"beach": 1, "holiday": 1, "trip": 1, "sea": 1,
	"dentist": 2, "tooth": 2, "appointment": 2,
	"garden": 3, "roses": 3, "plants": 3,
}

func (f *fakeEmbed) Embed(_ context.Context, texts []string) ([][]float32, Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.maxTexts = max(f.maxTexts, len(texts))
	if f.down {
		return nil, Info{}, errors.New("unavailable: socket refused")
	}
	model, dim := PinnedModel, PinnedDim
	if f.model != "" {
		model = f.model
	}
	if f.dim != 0 {
		dim = f.dim
	}
	out := make([][]float32, 0, len(texts))
	for _, t := range texts {
		v := make([]float32, dim)
		for _, w := range strings.FieldsFunc(strings.ToLower(t), func(r rune) bool { return strings.ContainsRune(" \n.,!?:;", r) }) {
			if c, ok := concepts[w]; ok {
				v[c%dim]++
				continue
			}
			s := sha256.Sum256([]byte(w))
			v[(8+int(s[0])%200)%dim] += 0.05
		}
		v[(Dim-1)%dim] += 0.01
		v[dim-1] += 5 // past Dim: truncation drops it
		switch {
		case f.nan:
			v[3] = float32(math.NaN())
		case f.inf:
			v[dim-1] = float32(math.Inf(1))
		case f.zero:
			clear(v)
		}
		out = append(out, v)
	}
	if f.extra {
		out = append(out, out[0])
	}
	return out, Info{SHA256: model, Dim: dim}, nil
}

var errGone = errors.New("kernel: that subject is erased")

type memItem struct {
	subject, class string
	data           []byte
}

// memContent is an in-memory content store: an erased subject's items
// can no longer be read.
type memContent struct {
	mu       sync.Mutex
	items    map[Hash]memItem
	order    []Hash
	erased   map[string]bool
	lineages []string
	n        int
}

func newMem() *memContent {
	return &memContent{items: map[Hash]memItem{}, erased: map[string]bool{}}
}

func (m *memContent) Seal(subject, class string, data []byte) (Hash, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.erased[subject] {
		return Hash{}, errGone
	}
	m.n++
	h := sha256.Sum256(fmt.Appendf(nil, "%d|%s|%s|%x", m.n, subject, class, data))
	m.items[h] = memItem{subject, class, slices.Clone(data)}
	m.order = append(m.order, h)
	return h, nil
}

func (m *memContent) ReadFor(h Hash, lineage string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lineages = append(m.lineages, lineage)
	it, ok := m.items[h]
	if !ok || m.erased[it.subject] {
		return nil, errGone
	}
	return slices.Clone(it.data), nil
}

func (m *memContent) erase(subject string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.erased[subject] = true
}

func (m *memContent) list() []Item {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Item
	for _, h := range m.order {
		it := m.items[h]
		out = append(out, Item{Subject: it.subject, Hash: h, Class: it.class})
	}
	return out
}

func (m *memContent) vectorItems() []memItem {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []memItem
	for _, h := range m.order {
		if it := m.items[h]; it.class == VectorClass {
			out = append(out, it)
		}
	}
	return out
}

func gone(err error) bool { return errors.Is(err, errGone) }

func newIndex(t *testing.T, e Embedder, c Content, capChunks int) *Index {
	t.Helper()
	ix, err := New(e, c, PinnedModel, PinnedDim, capChunks)
	if err != nil {
		t.Fatal(err)
	}
	ix.Gone = gone
	return ix
}

// source seals text as a source item under subject and returns its hash.
func source(t *testing.T, m *memContent, subject, text string) Hash {
	t.Helper()
	h, err := m.Seal(subject, "mail", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func addAll(t *testing.T, ix *Index, m *memContent, docs map[string]string) map[string]Hash {
	t.Helper()
	out := map[string]Hash{}
	for _, sub := range slices.Sorted(mapKeys(docs)) {
		h := source(t, m, sub, docs[sub])
		if err := ix.Add(context.Background(), sub, h, docs[sub]); err != nil {
			t.Fatalf("Add %s: %v", sub, err)
		}
		out[sub] = h
	}
	return out
}

func mapKeys(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

var docs = map[string]string{
	"s-invoice": "The invoice for March is attached. Payment is owed by Friday.",
	"s-beach":   "Photos from our trip to the beach and the sea last summer.",
	"s-dentist": "Your dentist appointment is moved to Tuesday at nine.",
	"s-garden":  "The roses in the garden need water and the plants need feeding.",
}

func subjects(hits []Hit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.Subject)
	}
	return out
}

func TestAddSealsVectorsUnderSourceSubject(t *testing.T) {
	m := newMem()
	ix := newIndex(t, &fakeEmbed{}, m, 0)
	text := strings.Repeat("The invoice is attached. ", 200) // about 5 KB: three chunks
	src := source(t, m, "s1", text)
	if err := ix.Add(context.Background(), "s1", src, text); err != nil {
		t.Fatal(err)
	}
	vs := m.vectorItems()
	if len(vs) != 1 {
		t.Fatalf("vector items = %d, want 1", len(vs))
	}
	if vs[0].subject != "s1" {
		t.Fatalf("vector item under subject %q, want the source's s1", vs[0].subject)
	}
	r, err := decode(vs[0].data)
	if err != nil {
		t.Fatal(err)
	}
	chunks, _ := Chunk(text)
	if r.model != PinnedModel || r.dim != Dim || r.source != src || len(r.vecs) != len(chunks) || len(chunks) < 3 {
		t.Fatalf("record model %s dim %d source ok %v chunks %d (want %d)", r.model, r.dim, r.source == src, len(r.vecs), len(chunks))
	}
	if st := ix.Stats(); st.Items != 1 || st.Chunks != len(chunks) || st.Pending != 0 {
		t.Fatalf("stats %+v", st)
	}
	// A second Add of the same source seals nothing more.
	if err := ix.Add(context.Background(), "s1", src, text); err != nil || len(m.vectorItems()) != 1 {
		t.Fatalf("re-Add: %v, %d items", err, len(m.vectorItems()))
	}
}

func TestSearchRanksByMeaning(t *testing.T) {
	m := newMem()
	ix := newIndex(t, &fakeEmbed{}, m, 0)
	addAll(t, ix, m, docs)
	for q, want := range map[string]string{
		"which bill do I still have to pay": "s-invoice",
		"holiday by the sea":                "s-beach",
		"tooth check-up":                    "s-dentist",
	} {
		hits, err := ix.Search(context.Background(), q, 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 3 || hits[0].Subject != want {
			t.Errorf("%q ranked %v, want %s first", q, subjects(hits), want)
		}
		if hits[0].Score <= hits[1].Score {
			t.Errorf("%q: top score %v not above %v", q, hits[0].Score, hits[1].Score)
		}
	}
	for _, k := range []int{0, MaxK + 1} {
		if _, err := ix.Search(context.Background(), "bill", k); !errors.Is(err, ErrQuery) {
			t.Errorf("k=%d: %v, want ErrQuery", k, err)
		}
	}
	if _, err := ix.Search(context.Background(), strings.Repeat("a", MaxChunk+1), 1); !errors.Is(err, ErrQuery) {
		t.Errorf("long query: %v, want ErrQuery", err)
	}
}

func TestRewindDropsSubjectAtOnce(t *testing.T) {
	m := newMem()
	ix := newIndex(t, &fakeEmbed{}, m, 0)
	addAll(t, ix, m, docs)
	ix.Rewind("s-invoice")
	hits, err := ix.Search(context.Background(), "bill to pay", MaxK)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(subjects(hits), "s-invoice") {
		t.Fatalf("hits after Rewind name the erased subject: %v", subjects(hits))
	}
	if st := ix.Stats(); st.Items != 3 {
		t.Fatalf("items = %d, want 3", st.Items)
	}
	// An Add for that subject after its erase indexes nothing.
	if err := ix.Add(context.Background(), "s-invoice", Hash{9}, "another invoice"); err != nil {
		t.Fatal(err)
	}
	hits, _ = ix.Search(context.Background(), "bill to pay", MaxK)
	if slices.Contains(subjects(hits), "s-invoice") {
		t.Fatal("an Add after Rewind brought the subject back")
	}
}

func TestReconcileDropsGoneItems(t *testing.T) {
	m := newMem()
	ix := newIndex(t, &fakeEmbed{}, m, 0)
	addAll(t, ix, m, docs)
	m.erase("s-beach") // no Rewind: the notice was lost
	if err := ix.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	hits, err := ix.Search(context.Background(), "holiday by the sea", MaxK)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(subjects(hits), "s-beach") {
		t.Fatalf("Reconcile left a gone item: %v", subjects(hits))
	}
	if len(hits) != 3 {
		t.Fatalf("Reconcile dropped too much: %v", subjects(hits))
	}
	for _, l := range m.lineages {
		if l != Lineage {
			t.Fatalf("a read under %q", l)
		}
	}
}

func TestRebuildEqualsLiveIndex(t *testing.T) {
	m := newMem()
	live := newIndex(t, &fakeEmbed{}, m, 0)
	addAll(t, live, m, docs)
	m.lineages = nil
	rebuilt := newIndex(t, &fakeEmbed{}, m, 0)
	if err := rebuilt.Rebuild(context.Background(), m.list()); err != nil {
		t.Fatal(err)
	}
	if len(m.vectorItems()) != len(docs) {
		t.Fatalf("rebuild sealed more vector items: %d", len(m.vectorItems()))
	}
	if a, b := live.Stats(), rebuilt.Stats(); a != b {
		t.Fatalf("stats live %+v, rebuilt %+v", a, b)
	}
	for _, q := range []string{"bill", "holiday by the sea", "tooth", "roses", "nothing in common"} {
		a, err1 := live.Search(context.Background(), q, MaxK)
		b, err2 := rebuilt.Search(context.Background(), q, MaxK)
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		if !slices.Equal(a, b) {
			t.Errorf("%q: live %v, rebuilt %v", q, a, b)
		}
	}
	if len(m.lineages) == 0 {
		t.Fatal("rebuild read nothing")
	}
	for _, l := range m.lineages {
		if l != Lineage {
			t.Fatalf("rebuild read under %q, want %s", l, Lineage)
		}
	}
}

func TestUnavailableIsNotEmpty(t *testing.T) {
	m := newMem()
	f := &fakeEmbed{down: true}
	ix := newIndex(t, f, m, 0)
	hits, err := ix.Search(context.Background(), "bill", 5)
	if !errors.Is(err, ErrUnavailable) || hits != nil {
		t.Fatalf("Search with the service down = %v, %v; want ErrUnavailable and no list", hits, err)
	}
	text := docs["s-invoice"]
	src := source(t, m, "s-invoice", text)
	if err := ix.Add(context.Background(), "s-invoice", src, text); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Add with the service down = %v", err)
	}
	if len(m.vectorItems()) != 0 || ix.Stats().Pending != 1 {
		t.Fatalf("sealed %d, pending %d", len(m.vectorItems()), ix.Stats().Pending)
	}
	if err := ix.Retry(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Retry while down = %v", err)
	}
	f.mu.Lock()
	f.down = false
	f.mu.Unlock()
	if err := ix.Retry(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := ix.Stats(); st.Pending != 0 || st.Items != 1 {
		t.Fatalf("after Retry: %+v", st)
	}
	hits, err = ix.Search(context.Background(), "bill", 5)
	if err != nil || len(hits) != 1 || hits[0].Source != src {
		t.Fatalf("after Retry: %v, %v", hits, err)
	}
	// An empty index with the service up is an empty list, not an error.
	empty := newIndex(t, &fakeEmbed{}, newMem(), 0)
	if hits, err := empty.Search(context.Background(), "bill", 5); err != nil || len(hits) != 0 {
		t.Fatalf("empty index: %v, %v", hits, err)
	}
}

func TestUntrustedVectorsRejected(t *testing.T) {
	for name, f := range map[string]*fakeEmbed{
		"wrong dim":        {dim: 512},
		"NaN":              {nan: true},
		"Inf":              {inf: true},
		"zero":             {zero: true},
		"wrong count":      {extra: true},
		"other model hash": {model: strings.Repeat("ab", 32)},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMem()
			ix := newIndex(t, f, m, 0)
			text := docs["s-invoice"]
			src := source(t, m, "s-invoice", text)
			if err := ix.Add(context.Background(), "s-invoice", src, text); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Add = %v, want ErrUnavailable", err)
			}
			if n := len(m.vectorItems()); n != 0 {
				t.Fatalf("sealed %d vector items", n)
			}
			if st := ix.Stats(); st.Pending != 1 || st.Chunks != 0 {
				t.Fatalf("stats %+v", st)
			}
			if _, err := ix.Search(context.Background(), "bill", 5); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("Search = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestMalformedVectorItemSkipped(t *testing.T) {
	m := newMem()
	ix := newIndex(t, &fakeEmbed{}, m, 0)
	srcs := addAll(t, ix, m, docs)
	good := m.vectorItems()[0].data
	for _, b := range [][]byte{
		good[:len(good)-1],                      // truncated
		append(slices.Clone(good), 0),           // trailing byte
		[]byte("not a vector item"),             // foreign
		nil,                                     // empty
		append([]byte("RETV\x02"), good[5:]...), // another version
		func() []byte { // a NaN scale
			b := slices.Clone(good)
			copy(b[headerSize:], []byte{0, 0, 0xc0, 0x7f})
			return b
		}(),
		func() []byte { // more chunks than the bound
			b := slices.Clone(good)
			b[71], b[72] = MaxChunks+1, 0
			return b
		}(),
	} {
		if _, err := m.Seal("s-bad", VectorClass, b); err != nil {
			t.Fatal(err)
		}
	}
	rebuilt := newIndex(t, &fakeEmbed{}, m, 0)
	if err := rebuilt.Rebuild(context.Background(), m.list()); err != nil {
		t.Fatal(err)
	}
	st := rebuilt.Stats()
	if st.Skipped != 7 || st.Items != len(srcs) {
		t.Fatalf("stats %+v, want 7 skipped and %d items", st, len(srcs))
	}
}

func TestChunkBounds(t *testing.T) {
	para := strings.Repeat("Ünïcödé wörds hère. ", 60) // about 1.6 KB
	cases := map[string]string{
		"paragraphs": strings.Repeat(para+"\n\n", 20),
		"one run":    strings.Repeat("é", 200_000),
		"emoji":      strings.Repeat("a😀", 50_000),
		"no breaks":  strings.Repeat("x", 3*MaxChunk+5),
		"invalid":    strings.Repeat("ab\xff\xfe", 3000),
		"short":      "hello",
		"blank":      "   \n\n   ",
	}
	for name, text := range cases {
		chunks, over := Chunk(text)
		if len(chunks) > MaxChunks {
			t.Errorf("%s: %d chunks", name, len(chunks))
		}
		total := over
		for _, c := range chunks {
			if len(c) > MaxChunk || len(c) == 0 {
				t.Errorf("%s: chunk of %d bytes", name, len(c))
			}
			if !utf8.ValidString(c) {
				t.Errorf("%s: a chunk splits a UTF-8 sequence", name)
			}
			total += len(c)
		}
		if valid := strings.ToValidUTF8(text, "�"); name != "blank" && total > len(valid) {
			t.Errorf("%s: chunks and overflow %d exceed the text %d", name, total, len(valid))
		}
		if name == "paragraphs" {
			for _, c := range chunks[:len(chunks)-1] {
				if !strings.HasSuffix(c, "\n\n") {
					t.Fatalf("paragraphs: a chunk not cut at a paragraph: ...%q", c[max(0, len(c)-10):])
				}
			}
		}
	}
	if chunks, over := Chunk(cases["one run"]); len(chunks) != MaxChunks || over == 0 {
		t.Errorf("one run: %d chunks, overflow %d; want %d and some", len(chunks), over, MaxChunks)
	}
	// The overflow is counted in Stats and no Embed call carries more
	// than MaxChunks texts.
	f := &fakeEmbed{}
	m := newMem()
	ix := newIndex(t, f, m, 0)
	text := cases["one run"]
	if err := ix.Add(context.Background(), "s", source(t, m, "s", text), text); err != nil {
		t.Fatal(err)
	}
	if st := ix.Stats(); st.Chunks != MaxChunks || st.UnindexedBytes == 0 {
		t.Fatalf("stats %+v", st)
	}
	if f.maxTexts > MaxChunks {
		t.Fatalf("an Embed call carried %d texts", f.maxTexts)
	}
}

func TestIndexFullLeavesItemsUnindexed(t *testing.T) {
	m := newMem()
	ix := newIndex(t, &fakeEmbed{}, m, 2)
	if err := ix.Add(context.Background(), "a", source(t, m, "a", "invoice"), "invoice"); err != nil {
		t.Fatal(err)
	}
	if err := ix.Add(context.Background(), "b", source(t, m, "b", "beach"), "beach"); err != nil {
		t.Fatal(err)
	}
	if err := ix.Add(context.Background(), "c", source(t, m, "c", "roses"), "roses"); !errors.Is(err, ErrFull) {
		t.Fatalf("Add past the cap = %v, want ErrFull", err)
	}
	st := ix.Stats()
	if st.Chunks != 2 || st.Full != 1 || st.Pending != 0 || len(m.vectorItems()) != 2 {
		t.Fatalf("stats %+v, %d vector items", st, len(m.vectorItems()))
	}
	// A rebuild under the same cap leaves it unindexed too, and says so.
	rebuilt := newIndex(t, &fakeEmbed{}, m, 2)
	if err := rebuilt.Rebuild(context.Background(), m.list()); err != nil {
		t.Fatal(err)
	}
	if st := rebuilt.Stats(); st.Chunks != 2 || st.Full != 1 {
		t.Fatalf("rebuilt stats %+v", st)
	}
}

func TestModelChangeReembeds(t *testing.T) {
	m := newMem()
	old := strings.Repeat("cd", 32)
	text := docs["s-garden"]
	src := source(t, m, "s-garden", text)
	// A vector item an earlier model sealed.
	v := make([]float32, PinnedDim)
	v[0] = 1
	qv, _ := quantise(v)
	if _, err := m.Seal("s-garden", VectorClass, encode(record{model: old, source: src, dim: Dim, vecs: []qvec{qv}})); err != nil {
		t.Fatal(err)
	}
	ix := newIndex(t, &fakeEmbed{}, m, 0)
	if err := ix.Rebuild(context.Background(), m.list()); err != nil {
		t.Fatal(err)
	}
	st := ix.Stats()
	if st.Stale != 1 || st.Items != 1 || st.Pending != 0 {
		t.Fatalf("stats %+v", st)
	}
	vs := m.vectorItems()
	if len(vs) != 2 {
		t.Fatalf("vector items = %d, want the old one and a new one", len(vs))
	}
	r, err := decode(vs[1].data)
	if err != nil || r.model != PinnedModel || r.source != src || vs[1].subject != "s-garden" {
		t.Fatalf("new item: %+v, %v", r.model, err)
	}
	hits, err := ix.Search(context.Background(), "roses and plants", 1)
	if err != nil || len(hits) != 1 || hits[0].Source != src {
		t.Fatalf("search: %v, %v", hits, err)
	}
	// The old item was never searched: a query on its one dim (invoice)
	// still ranks the garden by the new vectors only.
	for _, l := range m.lineages {
		if l != Lineage {
			t.Fatalf("read under %q", l)
		}
	}
}

func TestLogsCarryNoText(t *testing.T) {
	const canary = "CANARY-7f3a9c-retrieve"
	var buf strings.Builder
	logf := func(format string, args ...any) { fmt.Fprintf(&buf, format+"\n", args...) }
	m := newMem()
	text := "invoice " + canary + " owed"
	for _, f := range []*fakeEmbed{{}, {down: true}, {nan: true}, {extra: true}} {
		ix := newIndex(t, f, m, 1)
		ix.Logf = logf
		src := source(t, m, "s", text)
		errs := []error{
			ix.Add(context.Background(), "s", src, text),
			ix.Add(context.Background(), "t", source(t, m, "t", text+" again"), text+" again"),
			ix.Retry(context.Background()),
			ix.Reconcile(context.Background()),
			ix.Rebuild(context.Background(), m.list()),
		}
		_, err := ix.Search(context.Background(), "bill "+canary, 3)
		errs = append(errs, err)
		for _, e := range errs {
			if e != nil && strings.Contains(e.Error(), canary) {
				t.Errorf("an error carries the canary: %v", e)
			}
		}
	}
	m.Seal("s", VectorClass, []byte(canary))
	ix := newIndex(t, &fakeEmbed{}, m, 0)
	ix.Logf = logf
	_ = ix.Rebuild(context.Background(), m.list())
	if buf.Len() == 0 {
		t.Fatal("nothing was logged; the test proves nothing")
	}
	if strings.Contains(buf.String(), canary) || strings.Contains(buf.String(), "invoice") {
		t.Fatalf("a log line carries text:\n%s", buf.String())
	}
}
