package recall

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCapacity is the BOARD P3-3 capacity measurement: ingest N synthetic
// mail-sized items into a file store, then measure the store's size, the
// broker's memory, the load time of a restart, a deletion, and a search.
// It runs only when RECALL_CAPACITY names N (e.g. 100000), since it takes
// minutes and gigabytes:
//
//	RECALL_CAPACITY=100000 go test ./recall -run TestCapacity -v -timeout 60m
func TestCapacity(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("RECALL_CAPACITY"))
	if n <= 0 {
		t.Skip("set RECALL_CAPACITY=N to run the capacity measurement")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "recall")
	st, err := OpenDir(path)
	if err != nil {
		t.Fatal(err)
	}
	ix, err := Open(st, WithKeyer(testKeyer(t)))
	if err != nil {
		t.Fatal(err)
	}
	gen := newMailGen(1)
	start := time.Now()
	batch := capacityBatch()
	for i := 0; i < n; i += batch {
		items := make([]Item, 0, batch)
		for j := i; j < n && j < i+batch; j++ {
			items = append(items, gen.item(j))
		}
		if _, err := ingestAll(ix, items); err != nil {
			t.Fatal(err)
		}
	}
	ingest := time.Since(start)
	size := fileSize(t, dir)
	rssLive := rss()

	q := Query{Text: gen.query(), Limit: 10}
	start = time.Now()
	const searches = 20
	for i := 0; i < searches; i++ {
		ix.Lookup(q)
	}
	search := time.Since(start) / searches

	start = time.Now()
	if _, err := ix.Delete(ix.SourceID("mail", "owner@example.test", gen.ref(n/2))); err != nil {
		t.Fatal(err)
	}
	del := time.Since(start)
	st.Close()

	ix, st = nil, nil
	runtime.GC()
	debug.FreeOSMemory()
	base := rss()
	start = time.Now()
	st, err = OpenDir(path)
	if err != nil {
		t.Fatal(err)
	}
	ix2, err := Open(st, WithKeyer(testKeyer(t)))
	if err != nil {
		t.Fatal(err)
	}
	load := time.Since(start)
	runtime.GC()
	rssLoaded := rss()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	heap := ms.HeapAlloc
	if ix2.Len() != n-1 {
		t.Fatalf("reopened with %d items, want %d", ix2.Len(), n-1)
	}
	st.Close()

	t.Logf("items=%d batch=%d ingest=%s (%.0f/s) store=%.1f MiB rss_after_ingest=%.0f MiB rss_after_load=%.0f MiB (base %.0f) heap_live=%.0f MiB load=%s delete_one=%s search=%s",
		n, batch, ingest.Round(time.Millisecond), float64(n)/ingest.Seconds(), float64(size)/(1<<20),
		float64(rssLive)/(1<<20), float64(rssLoaded)/(1<<20), float64(base)/(1<<20), float64(heap)/(1<<20),
		load.Round(time.Millisecond), del.Round(time.Millisecond), search.Round(time.Microsecond))
}

func capacityBatch() int {
	if b, _ := strconv.Atoi(os.Getenv("RECALL_CAPACITY_BATCH")); b > 0 {
		return b
	}
	return 1
}

// ingestAll ingests items one by one, or as one batch.
func ingestAll(ix *Index, items []Item) (int, error) {
	if len(items) > 1 {
		_, errs := ix.IngestBatch(items)
		for _, err := range errs {
			if err != nil {
				return 0, err
			}
		}
		return len(items), nil
	}
	for _, it := range items {
		if _, err := ix.Ingest(it); err != nil {
			return 0, err
		}
	}
	return len(items), nil
}

func fileSize(t *testing.T, dir string) int64 {
	var total int64
	filepath.Walk(dir, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			total += fi.Size()
		}
		return nil
	})
	return total
}

// rss is the process's resident set from /proc (Linux), or the Go heap in
// use where /proc is absent.
func rss() int64 {
	b, err := os.ReadFile("/proc/self/status")
	if err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "VmRSS:") {
				f := strings.Fields(l)
				if len(f) >= 2 {
					kb, _ := strconv.ParseInt(f[1], 10, 64)
					return kb << 10
				}
			}
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapInuse)
}

// mailGen makes synthetic mail: a subject and a body of about 300 words
// drawn Zipf-like from a 20k-word vocabulary, plus a few facts. All of it
// is made up; no real addresses or content (CLAUDE.md: synthetic only).
type mailGen struct {
	r     *rand.Rand
	z     *rand.Zipf
	vocab []string
}

func newMailGen(seed int64) *mailGen {
	r := rand.New(rand.NewSource(seed))
	g := &mailGen{r: r, z: rand.NewZipf(r, 1.1, 2, 19999)}
	syl := []string{"ka", "lo", "mi", "ne", "ru", "sa", "to", "vi", "be", "da", "fo", "gu", "ha", "ji", "pe", "qu", "we", "xo", "yo", "zi"}
	for i := 0; i < 20000; i++ {
		w := syl[i%20] + syl[(i/20)%20] + syl[(i/400)%20]
		if i >= 8000 {
			w += syl[(i/8000)%20]
		}
		g.vocab = append(g.vocab, w)
	}
	return g
}

func (g *mailGen) words(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(g.vocab[g.z.Uint64()])
	}
	return b.String()
}

func (g *mailGen) ref(i int) string { return fmt.Sprintf("<msg-%08d@mail.example.test>", i) }

func (g *mailGen) item(i int) Item {
	at := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * 30 * time.Minute)
	return Item{
		Source: Source{Kind: "mail", Account: "owner@example.test", Ref: g.ref(i), Seen: at},
		Text:   "Subject: " + g.words(6) + "\n\n" + g.words(250+g.r.Intn(100)),
		Facts: []Fact{
			{"msg-" + strconv.Itoa(i), "from", "sender" + strconv.Itoa(g.r.Intn(2000)) + "@example.test"},
			{"msg-" + strconv.Itoa(i), "topic", g.vocab[g.z.Uint64()]},
		},
		Received: at,
	}
}

func (g *mailGen) query() string { return g.vocab[40] + " " + g.vocab[900] + " " + g.vocab[5000] }

// R8: int8 vectors keep vector ranking close to float32. Over synthetic
// mail, the top 10 by quantized cosine overlap the float top 10 by at
// least 0.85 on average (measured 0.88 in review of #51).
func TestInt8RankingAccuracy(t *testing.T) {
	g := newMailGen(7)
	const n, queries, k = 1000, 40, 10
	texts := make([]string, n)
	for i := range texts {
		texts[i] = g.item(i).Text
	}
	var emb HashEmbedder
	vs, err := emb.Embed(texts)
	if err != nil {
		t.Fatal(err)
	}
	qs := make([][]int8, n)
	qn := make([]float32, n)
	for i, v := range vs {
		qs[i], _ = quantize(v)
		qn[i] = normQ(qs[i])
	}
	top := func(score func(i int) float64) map[int]bool {
		idx := make([]int, n)
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool { return score(idx[a]) > score(idx[b]) })
		out := map[int]bool{}
		for _, i := range idx[:k] {
			out[i] = true
		}
		return out
	}
	total := 0.0
	for q := 0; q < queries; q++ {
		qv, err := emb.Embed([]string{g.words(3)})
		if err != nil {
			t.Fatal(err)
		}
		a, an := qv[0], norm(qv[0])
		exact := top(func(i int) float64 { return cosine(a, vs[i]) })
		approx := top(func(i int) float64 { return cosineQ(a, an, qs[i], qn[i]) })
		hit := 0
		for i := range approx {
			if exact[i] {
				hit++
			}
		}
		total += float64(hit) / k
	}
	if avg := total / queries; avg < 0.85 {
		t.Fatalf("int8 top-%d overlap %.3f, floor 0.85", k, avg)
	} else {
		t.Logf("int8 top-%d overlap %.3f", k, avg)
	}
}
