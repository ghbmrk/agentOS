package recall

import (
	"hash/fnv"
	"math"
	"strings"
	"unicode"
)

// tokens splits text into lower-case words of letters and digits.
func tokens(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

// Embedder turns texts into vectors. The production embedder is the local
// inference service (SPEC §3: an untrusted service on the box); recall works
// without one, on full text and facts alone (DEP-1 style degradation).
type Embedder interface {
	Embed(texts []string) ([][]float32, error)
}

// HashEmbedder is a stdlib-only embedder: feature hashing of words and
// character trigrams, L2-normalised. It gives fuzzy matching (inflections,
// typos) with no model, and is the fallback when local inference is absent.
type HashEmbedder struct{ Dim int }

func (h HashEmbedder) Embed(texts []string) ([][]float32, error) {
	dim := h.Dim
	if dim <= 0 {
		dim = 512
	}
	out := make([][]float32, len(texts))
	for i, t := range texts {
		v := make([]float32, dim)
		for _, w := range tokens(t) {
			add(v, "w:"+w, 1)
			p := "^" + w + "$"
			r := []rune(p)
			for k := 0; k+3 <= len(r); k++ {
				add(v, "t:"+string(r[k:k+3]), 0.5)
			}
		}
		normalize(v)
		out[i] = v
	}
	return out, nil
}

func add(v []float32, feat string, w float32) {
	f := fnv.New64a()
	f.Write([]byte(feat))
	x := f.Sum64()
	i := int(x % uint64(len(v)))
	if x>>63 == 1 {
		w = -w
	}
	v[i] += w
}

func normalize(v []float32) {
	var s float64
	for _, x := range v {
		s += float64(x) * float64(x)
	}
	if s == 0 {
		return
	}
	n := float32(1 / math.Sqrt(s))
	for i := range v {
		v[i] *= n
	}
}

func cosine(a, b []float32) float64 {
	if len(a) == 0 || len(a) != len(b) {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / math.Sqrt(na*nb)
}

// BM25 parameters.
const (
	bm25K1 = 1.2
	bm25B  = 0.75
)

// textIndex is an inverted index with BM25 scoring.
type textIndex struct {
	post  map[string]map[string]int // term -> item -> term frequency
	dlen  map[string]int
	terms map[string][]string // item -> its distinct terms, for removal
	total int
}

func newTextIndex() *textIndex {
	return &textIndex{post: map[string]map[string]int{}, dlen: map[string]int{}, terms: map[string][]string{}}
}

func (t *textIndex) add(id, text string) {
	t.remove(id)
	ws := tokens(text)
	for _, w := range ws {
		m := t.post[w]
		if m == nil {
			m = map[string]int{}
			t.post[w] = m
		}
		if m[id] == 0 {
			t.terms[id] = append(t.terms[id], w)
		}
		m[id]++
	}
	t.dlen[id] = len(ws)
	t.total += len(ws)
}

func (t *textIndex) remove(id string) {
	n, ok := t.dlen[id]
	if !ok {
		return
	}
	for _, w := range t.terms[id] {
		m := t.post[w]
		delete(m, id)
		if len(m) == 0 {
			delete(t.post, w)
		}
	}
	delete(t.terms, id)
	delete(t.dlen, id)
	t.total -= n
}

func (t *textIndex) score(query string) map[string]float64 {
	out := map[string]float64{}
	n := len(t.dlen)
	if n == 0 {
		return out
	}
	avg := float64(t.total) / float64(n)
	if avg == 0 {
		avg = 1
	}
	seen := map[string]bool{}
	for _, w := range tokens(query) {
		if seen[w] {
			continue
		}
		seen[w] = true
		m := t.post[w]
		if len(m) == 0 {
			continue
		}
		df := float64(len(m))
		idf := math.Log(1 + (float64(n)-df+0.5)/(df+0.5))
		for id, tf := range m {
			f := float64(tf)
			dl := float64(t.dlen[id])
			out[id] += idf * f * (bm25K1 + 1) / (f + bm25K1*(1-bm25B+bm25B*dl/avg))
		}
	}
	return out
}
