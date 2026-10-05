package recall

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
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
//
// ID names the vector space (model, version, dimension). Vectors are stored
// with it and compared only with query vectors of the same ID, so a new
// embedder never compares across spaces; BM25 still answers meanwhile and
// Index.Reembed brings old vectors over.
type Embedder interface {
	ID() string
	Embed(texts []string) ([][]float32, error)
}

// CosineFloor is optional on an Embedder: the similarity below which a
// vector match alone is noise in its space. Without it, defaultMinCosine.
type CosineFloor interface {
	MinCosine() float64
}

const defaultMinCosine = 0.3

// HashEmbedder is a stdlib-only embedder: feature hashing of words and
// character trigrams, L2-normalised. It gives fuzzy matching (inflections,
// typos) with no model, and is the fallback when local inference is absent.
type HashEmbedder struct{ Dim int }

func (h HashEmbedder) dim() int {
	if h.Dim <= 0 {
		return 512
	}
	return h.Dim
}

// ID names the hashing space and its dimension.
func (h HashEmbedder) ID() string { return fmt.Sprintf("hash-v1/%d", h.dim()) }

// MinCosine is the noise floor measured for this embedder.
func (h HashEmbedder) MinCosine() float64 { return 0.2 }

func (h HashEmbedder) Embed(texts []string) ([][]float32, error) {
	dim := h.dim()
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

// textIndex is an inverted index with BM25 scoring over document numbers.
// Postings are kept sorted by document number in compact parallel slices
// (4 bytes of document and 1 of term frequency each), so 100k mail-sized
// items cost tens of megabytes rather than gigabytes (R8). Removal needs
// the document's text again; the index does not keep it.
type textIndex struct {
	post  map[string]*postings
	dlen  map[uint32]uint32
	total int
}

type postings struct {
	docs []uint32
	tf   []uint8
}

func newTextIndex() *textIndex {
	return &textIndex{post: map[string]*postings{}, dlen: map[uint32]uint32{}}
}

// termCounts counts text's terms; frequencies saturate at 255, which BM25's
// saturation makes immaterial.
func termCounts(text string) (map[string]int, int) {
	ws := tokens(text)
	c := make(map[string]int, len(ws)/2+1)
	for _, w := range ws {
		c[w]++
	}
	return c, len(ws)
}

// add indexes doc, which must be greater than every document added so far,
// so postings stay sorted by appending.
func (t *textIndex) add(doc uint32, text string) {
	c, n := termCounts(text)
	for w, f := range c {
		p := t.post[w]
		if p == nil {
			// Clone: w is a slice of the whole lowered text, which the
			// map key would otherwise keep alive.
			p = &postings{}
			t.post[strings.Clone(w)] = p
		}
		if f > 255 {
			f = 255
		}
		p.docs = append(p.docs, doc)
		p.tf = append(p.tf, uint8(f))
	}
	t.dlen[doc] = uint32(n)
	t.total += n
}

// remove drops doc, whose text was text when it was added.
func (t *textIndex) remove(doc uint32, text string) {
	n, ok := t.dlen[doc]
	if !ok {
		return
	}
	c, _ := termCounts(text)
	for w := range c {
		p := t.post[w]
		if p == nil {
			continue
		}
		i := sort.Search(len(p.docs), func(i int) bool { return p.docs[i] >= doc })
		if i < len(p.docs) && p.docs[i] == doc {
			p.docs = append(p.docs[:i], p.docs[i+1:]...)
			p.tf = append(p.tf[:i], p.tf[i+1:]...)
		}
		if len(p.docs) == 0 {
			delete(t.post, w)
		} else if cap(p.docs) > 64 && len(p.docs) < cap(p.docs)/4 {
			p.docs = append([]uint32(nil), p.docs...)
			p.tf = append([]uint8(nil), p.tf...)
		}
	}
	delete(t.dlen, doc)
	t.total -= int(n)
}

// trim drops the spare capacity appending left in posting lists, after a
// bulk load.
func (t *textIndex) trim() {
	for _, p := range t.post {
		if cap(p.docs) > len(p.docs)+len(p.docs)/8 {
			p.docs = append([]uint32(nil), p.docs...)
			p.tf = append([]uint8(nil), p.tf...)
		}
	}
}

func (t *textIndex) score(query string) map[uint32]float64 {
	out := map[uint32]float64{}
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
		p := t.post[w]
		if p == nil || len(p.docs) == 0 {
			continue
		}
		df := float64(len(p.docs))
		idf := math.Log(1 + (float64(n)-df+0.5)/(df+0.5))
		for i, doc := range p.docs {
			f := float64(p.tf[i])
			dl := float64(t.dlen[doc])
			out[doc] += idf * f * (bm25K1 + 1) / (f + bm25K1*(1-bm25B+bm25B*dl/avg))
		}
	}
	return out
}

// quantize stores a vector as int8 components scaled to its largest
// magnitude, with that scale (R8: binary vectors, a quarter of float32).
// Cosine similarity is scale-free, so search compares the int8 form
// directly.
func quantize(v []float32) (q []int8, scale float32) {
	var m float32
	for _, x := range v {
		if x < 0 {
			x = -x
		}
		if x > m {
			m = x
		}
	}
	q = make([]int8, len(v))
	if m == 0 {
		return q, 0
	}
	for i, x := range v {
		q[i] = int8(math.Round(float64(x / m * 127)))
	}
	return q, m / 127
}

func dequantize(q []int8, scale float32) []float32 {
	v := make([]float32, len(q))
	for i, x := range q {
		v[i] = float32(x) * scale
	}
	return v
}

// cosineQ is the cosine similarity of a float query and a quantized
// vector with precomputed norm.
func cosineQ(a []float32, an float64, b []int8, bn float32) float64 {
	if len(a) != len(b) || an == 0 || bn == 0 {
		return 0
	}
	var dot float64
	for i, x := range a {
		dot += float64(x) * float64(b[i])
	}
	return dot / (an * float64(bn))
}

func normQ(q []int8) float32 {
	var s float64
	for _, x := range q {
		s += float64(x) * float64(x)
	}
	return float32(math.Sqrt(s))
}

func norm(v []float32) float64 {
	var s float64
	for _, x := range v {
		s += float64(x) * float64(x)
	}
	return math.Sqrt(s)
}
