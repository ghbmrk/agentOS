// Package retrieve is the local retrieve pass's index (INFER-retrieve R1,
// PLN-7): the content clerk that sealed an item embeds its text through
// the local inference service, seals the vectors as one item of class
// VectorClass under the same subject, and keeps a searchable projection
// of them in memory only.
//
// Erase is by key: the vectors share the source's subject, so erasing the
// subject destroys them with the content (LOG-4). Rewind drops a subject's
// entries from memory at once, and Reconcile drops any whose sealed item
// ReadFor reports gone, bounding the window when no Rewind comes. The
// projection is rebuilt at start from the sealed items, every read under
// the one service lineage svc-retrieve, so a rebuild after a crash equals
// one from empty (LOG-1). Nothing unsealed is written to disk.
//
// A hit only ranks (KRN-3): it names a subject, a source item and a score,
// and reading the item stays the caller's ReadFor under its own lineage,
// which the kernel refuses for an erased item. The service is untrusted:
// every vector is checked here as well as in its client, and a service
// that is off, missing or misbehaving makes Search return ErrUnavailable,
// never an empty list.
//
// The package imports the standard library only and logs no text, query
// or vector (imports_test.go, TestLogsCarryNoText).
package retrieve

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
)

// Hash names a sealed kernel item: the SHA-256 of its ciphertext.
type Hash [32]byte

// Info is the model an Embed reply came from. R2 adapts infer.Client to
// Embedder by copying infer.Info's SHA256 and Dim; this package does not
// import infer (ASSUMPTIONS RET-A5).
type Info struct {
	SHA256 string
	Dim    int
}

// Embedder is the inference service's embed call: one vector per text,
// in order.
type Embedder interface {
	Embed(ctx context.Context, texts []string) ([][]float32, Info, error)
}

// Content is the kernel's content seam for the clerk's own store, as
// faces.Content: seal an item under a subject, and read one for a
// lineage, which the kernel logs before it answers.
type Content interface {
	Seal(subject, class string, data []byte) (Hash, error)
	ReadFor(h Hash, lineage string) ([]byte, error)
}

// Item is one sealed item the clerk's store holds, as the caller lists
// them to Rebuild: a VectorClass item, or a source to index if no vector
// item of the index's model covers it.
type Item struct {
	Subject string
	Hash    Hash
	Class   string
}

// Hit is a ranking proposal: never a decision (KRN-3).
type Hit struct {
	Subject string
	Source  Hash
	Score   float32
}

// Stats is the index's counts; it carries no text.
type Stats struct {
	Items   int // vector items in the projection
	Chunks  int // chunks in the projection
	Cap     int
	Pending int // sources waiting for the service (Retry)
	// Full counts sources left unindexed because the projection was at
	// Cap.
	Full int
	// UnindexedBytes is text past MaxChunks chunks, never indexed.
	UnindexedBytes int64
	// Skipped counts vector items Rebuild could not parse.
	Skipped int
	// Stale counts vector items of another model, ignored and kept
	// until their subject's erase.
	Stale int
}

const (
	// Lineage is the one lineage every read this package makes is logged
	// under (the svc-vision pattern, D-169).
	Lineage = "svc-retrieve"
	// VectorClass is a vector item's class as kernel content.
	VectorClass = "retrieve-vectors"
	// MaxChunk bounds a chunk's bytes, and a query's.
	MaxChunk = 2048
	// MaxChunks bounds an item's chunks, and so one Embed call's texts
	// (infer.MaxTexts is 64).
	MaxChunks = 64
	// Dim is the stored dims: the model's vectors are truncated to it and
	// renormalised (Matryoshka; ASSUMPTIONS RET-A2).
	Dim = 256
	// DefaultCap is the projection's chunk cap when Index.Cap is zero
	// (about 52 MB).
	DefaultCap = 200_000
	// MaxK bounds a search's hits.
	MaxK = 50
	// PinnedModel is the image's Qwen3-Embedding-0.6B Q8_0
	// (agentosd.service -infer-model-sha256).
	PinnedModel = "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439"
	// PinnedDim is that model's output dims.
	PinnedDim = 1024
)

// queryPrefix is each known model's query instruction; documents carry
// none. A model without one cannot be searched with, so New refuses it.
var queryPrefix = map[string]string{
	PinnedModel: "Instruct: Given a search query, retrieve relevant passages from the owner's mail and files\nQuery:",
}

// Errors a caller tells apart.
var (
	// ErrUnavailable is the service off, failing or answering something
	// this package does not accept: search is not possible, which is not
	// the same as no results.
	ErrUnavailable = errors.New("retrieve: the retrieve service is unavailable")
	ErrFull        = errors.New("retrieve: the index is full")
	ErrNoContent   = errors.New("retrieve: no content store")
	ErrQuery       = errors.New("retrieve: a query is 1 to 2048 bytes and k is 1 to 50")
	ErrModel       = errors.New("retrieve: no query instruction for that model")
)

// Index is the in-memory projection and the seams it is built through.
type Index struct {
	embed   Embedder
	content Content
	model   string
	prefix  string
	cap     int

	// Gone reports a ReadFor error that means the item can never be read
	// again (its subject erased, or the item unknown); any other error
	// leaves the entry in place until a later Reconcile.
	Gone func(error) bool
	// Text turns a source item's sealed bytes into its text, for Retry
	// and re-embedding; nil takes the bytes as UTF-8 text.
	Text func(data []byte) (string, error)
	// Logf receives counts and causes only, never text.
	Logf func(format string, args ...any)

	mu       sync.RWMutex
	entries  []entry
	items    map[Hash]itemInfo // vector item -> its source
	covered  map[Hash]Hash     // source -> vector item
	pending  map[Hash]string   // source -> subject
	inflight map[Hash]bool     // sources being embedded
	erased   map[string]bool   // subjects Rewind was told of
	full     int
	overflow int64
	skipped  int
	stale    int
}

type entry struct {
	subject string
	source  Hash
	item    Hash
	scale   float32
	vec     []int8
}

type itemInfo struct {
	subject string
	source  Hash
}

// New returns an empty index over e and c for the model named by its
// SHA-256 and output dims; capChunks zero is DefaultCap.
func New(e Embedder, c Content, model string, modelDim, capChunks int) (*Index, error) {
	prefix, ok := queryPrefix[model]
	if !ok || modelDim != PinnedDim {
		return nil, ErrModel
	}
	if capChunks <= 0 {
		capChunks = DefaultCap
	}
	ix := &Index{embed: e, content: c, model: model, prefix: prefix, cap: capChunks}
	ix.reset()
	return ix, nil
}

func (ix *Index) reset() {
	ix.entries = nil
	ix.items = map[Hash]itemInfo{}
	ix.covered = map[Hash]Hash{}
	ix.pending = map[Hash]string{}
	ix.inflight = map[Hash]bool{}
	ix.full, ix.overflow, ix.skipped, ix.stale = 0, 0, 0, 0
	if ix.erased == nil {
		ix.erased = map[string]bool{}
	}
}

func (ix *Index) logf(format string, args ...any) {
	if ix.Logf != nil {
		ix.Logf(format, args...)
	}
}

// Add embeds the text of source, sealed under subject, and seals its
// vectors under the same subject. The caller holds the text from sealing
// the source, so nothing is read back. If the service is unavailable, or
// its answer is refused, nothing is sealed, the source stays pending and
// Retry indexes it later; the error wraps ErrUnavailable.
func (ix *Index) Add(ctx context.Context, subject string, source Hash, text string) error {
	ix.mu.Lock()
	if _, ok := ix.covered[source]; ok || ix.inflight[source] || ix.erased[subject] {
		ix.mu.Unlock()
		return nil
	}
	ix.inflight[source] = true
	ix.mu.Unlock()
	err := ix.add(ctx, subject, source, text)
	ix.mu.Lock()
	delete(ix.inflight, source)
	switch {
	case err == nil, errors.Is(err, ErrFull):
		delete(ix.pending, source)
	case !ix.erased[subject]:
		ix.pending[source] = subject
	}
	ix.mu.Unlock()
	return err
}

func (ix *Index) add(ctx context.Context, subject string, source Hash, text string) error {
	if ix.content == nil {
		return ErrNoContent
	}
	chunks, over := Chunk(text)
	ix.mu.Lock()
	room := len(ix.entries)+len(chunks) <= ix.cap
	if !room {
		ix.full++
	}
	ix.mu.Unlock()
	if !room {
		ix.logf("retrieve: index full at %d chunks; a source of %d chunks left unindexed", ix.cap, len(chunks))
		return ErrFull
	}
	var vecs []qvec
	if len(chunks) > 0 {
		raw, info, err := ix.embed.Embed(ctx, chunks)
		if err != nil {
			ix.logf("retrieve: embed failed (%d chunks): %s", len(chunks), causeOf(err))
			return fmt.Errorf("%w: embed failed", ErrUnavailable)
		}
		if vecs, err = ix.check(raw, info, len(chunks)); err != nil {
			ix.logf("retrieve: embed reply refused (%d chunks): %v", len(chunks), err)
			return err
		}
	}
	data := encode(record{model: ix.model, source: source, dim: Dim, overflow: uint32(min(over, math.MaxUint32)), vecs: vecs})
	h, err := ix.content.Seal(subject, VectorClass, data)
	if err != nil {
		ix.logf("retrieve: sealing a vector item failed")
		return fmt.Errorf("retrieve: sealing the vectors: %w", err)
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if ix.erased[subject] {
		return nil
	}
	ix.insert(subject, h, source, vecs, int64(over))
	return nil
}

// insert puts one vector item's chunks in the projection; the caller
// holds mu.
func (ix *Index) insert(subject string, item, source Hash, vecs []qvec, over int64) {
	if old, ok := ix.covered[source]; ok {
		ix.drop(func(e entry) bool { return e.item == old })
		delete(ix.items, old)
	}
	for _, v := range vecs {
		ix.entries = append(ix.entries, entry{subject: subject, source: source, item: item, scale: v.scale, vec: v.vec})
	}
	ix.items[item] = itemInfo{subject: subject, source: source}
	ix.covered[source] = item
	ix.overflow += over
}

// drop removes the entries f names; the caller holds mu.
func (ix *Index) drop(f func(entry) bool) {
	ix.entries = slices.DeleteFunc(ix.entries, f)
}

// check is the library's own check of an embed reply, beyond the
// client's: the count, the model, the dims and every value.
func (ix *Index) check(raw [][]float32, info Info, n int) ([]qvec, error) {
	switch {
	case len(raw) != n:
		return nil, fmt.Errorf("%w: wrong vector count", ErrUnavailable)
	case info.SHA256 != ix.model:
		return nil, fmt.Errorf("%w: another model", ErrUnavailable)
	case info.Dim != PinnedDim:
		return nil, fmt.Errorf("%w: wrong dim", ErrUnavailable)
	}
	out := make([]qvec, 0, n)
	for _, v := range raw {
		if len(v) != PinnedDim {
			return nil, fmt.Errorf("%w: wrong dim", ErrUnavailable)
		}
		q, ok := quantise(v)
		if !ok {
			return nil, fmt.Errorf("%w: non-finite or zero vector", ErrUnavailable)
		}
		out = append(out, q)
	}
	return out, nil
}

// Search embeds query and returns at most k sources, best first, each
// scored by its best chunk. An index with nothing in it answers an empty
// list; a service that cannot answer is ErrUnavailable.
func (ix *Index) Search(ctx context.Context, query string, k int) ([]Hit, error) {
	if query == "" || len(query) > MaxChunk || k < 1 || k > MaxK {
		return nil, ErrQuery
	}
	raw, info, err := ix.embed.Embed(ctx, []string{ix.prefix + strings.ToValidUTF8(query, "�")})
	if err != nil {
		ix.logf("retrieve: query embed failed: %s", causeOf(err))
		return nil, fmt.Errorf("%w: embed failed", ErrUnavailable)
	}
	qs, err := ix.check(raw, info, 1)
	if err != nil {
		ix.logf("retrieve: query embed reply refused: %v", err)
		return nil, err
	}
	q := qs[0]
	ix.mu.RLock()
	best := map[Hash]Hit{}
	for _, e := range ix.entries {
		s := float32(dot(q.vec, e.vec)) * q.scale * e.scale
		if h, ok := best[e.source]; !ok || s > h.Score {
			best[e.source] = Hit{Subject: e.subject, Source: e.source, Score: s}
		}
	}
	ix.mu.RUnlock()
	hits := make([]Hit, 0, len(best))
	for _, h := range best {
		hits = append(hits, h)
	}
	slices.SortFunc(hits, func(a, b Hit) int {
		if c := cmp.Compare(b.Score, a.Score); c != 0 {
			return c
		}
		return slices.Compare(a.Source[:], b.Source[:])
	})
	return hits[:min(k, len(hits))], nil
}

// Rewind drops subject's entries and pending sources at once: the erase
// notice's seam (faces.Rewind). A subject once rewound is never indexed
// again by this index, so an Add in flight cannot bring it back.
func (ix *Index) Rewind(subject string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.erased[subject] = true
	ix.drop(func(e entry) bool { return e.subject == subject })
	for h, it := range ix.items {
		if it.subject == subject {
			delete(ix.items, h)
			delete(ix.covered, it.source)
		}
	}
	for src, sub := range ix.pending {
		if sub == subject {
			delete(ix.pending, src)
		}
	}
}

// Reconcile reads every vector item in the projection again under
// Lineage and drops those ReadFor reports gone, so an erase whose notice
// was lost leaves the projection within one period. Other read errors
// leave the item for the next Reconcile; they are returned joined.
func (ix *Index) Reconcile(ctx context.Context) error {
	if ix.content == nil {
		return ErrNoContent
	}
	ix.mu.RLock()
	hs := make([]Hash, 0, len(ix.items))
	for h := range ix.items {
		hs = append(hs, h)
	}
	ix.mu.RUnlock()
	var gone []Hash
	var errs []error
	for _, h := range hs {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		b, err := ix.content.ReadFor(h, Lineage)
		clear(b)
		switch {
		case err == nil:
		case ix.Gone != nil && ix.Gone(err):
			gone = append(gone, h)
		default:
			errs = append(errs, err)
		}
	}
	ix.mu.Lock()
	for _, h := range gone {
		it, ok := ix.items[h]
		if !ok {
			continue
		}
		ix.drop(func(e entry) bool { return e.item == h })
		delete(ix.items, h)
		if ix.covered[it.source] == h {
			delete(ix.covered, it.source)
		}
	}
	ix.mu.Unlock()
	if len(gone) > 0 {
		ix.logf("retrieve: reconcile dropped %d gone vector items", len(gone))
	}
	return errors.Join(errs...)
}

// Rebuild replaces the projection with one built from items, every read
// under Lineage: each vector item of the index's model is parsed and
// added; one of another model is ignored and its source re-embedded; a
// malformed one is counted and skipped. A source item (any other class)
// that no vector item covers is embedded, or left pending if the service
// cannot answer. Pending sources from before are kept for Retry.
func (ix *Index) Rebuild(ctx context.Context, items []Item) error {
	if ix.content == nil {
		return ErrNoContent
	}
	ix.mu.Lock()
	pending := ix.pending
	ix.reset()
	ix.mu.Unlock()
	type src struct {
		subject string
		hash    Hash
	}
	var todo []src
	var errs []error
	for _, it := range items {
		if it.Class != VectorClass {
			continue
		}
		b, err := ix.content.ReadFor(it.Hash, Lineage)
		if err != nil {
			if ix.Gone == nil || !ix.Gone(err) {
				errs = append(errs, err)
			}
			continue
		}
		r, err := decode(b)
		clear(b)
		ix.mu.Lock()
		switch {
		case err != nil:
			ix.skipped++
		case r.model != ix.model || r.dim != Dim:
			ix.stale++
			todo = append(todo, src{it.Subject, r.source})
		case ix.erased[it.Subject]:
		case len(ix.entries)+len(r.vecs) > ix.cap:
			ix.full++
		default:
			ix.insert(it.Subject, it.Hash, r.source, r.vecs, int64(r.overflow))
		}
		ix.mu.Unlock()
	}
	for _, it := range items {
		if it.Class != VectorClass {
			todo = append(todo, src{it.Subject, it.Hash})
		}
	}
	ix.mu.Lock()
	for _, s := range todo {
		if _, ok := ix.covered[s.hash]; !ok && !ix.erased[s.subject] {
			ix.pending[s.hash] = s.subject
		}
	}
	for h, sub := range pending {
		if _, ok := ix.covered[h]; !ok && !ix.erased[sub] {
			ix.pending[h] = sub
		}
	}
	skipped := ix.skipped
	ix.mu.Unlock()
	if skipped > 0 {
		ix.logf("retrieve: rebuild skipped %d malformed vector items", skipped)
	}
	if err := ix.Retry(ctx); err != nil && !errors.Is(err, ErrUnavailable) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Retry indexes the pending sources, reading each again under Lineage.
// It stops at the first ErrUnavailable, leaving the rest pending; a
// source ReadFor reports gone is dropped.
func (ix *Index) Retry(ctx context.Context) error {
	if ix.content == nil {
		return ErrNoContent
	}
	ix.mu.RLock()
	type src struct {
		hash    Hash
		subject string
	}
	todo := make([]src, 0, len(ix.pending))
	for h, sub := range ix.pending {
		todo = append(todo, src{h, sub})
	}
	ix.mu.RUnlock()
	slices.SortFunc(todo, func(a, b src) int { return slices.Compare(a.hash[:], b.hash[:]) })
	var errs []error
	for _, s := range todo {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		b, err := ix.content.ReadFor(s.hash, Lineage)
		if err != nil {
			if ix.Gone != nil && ix.Gone(err) {
				ix.mu.Lock()
				delete(ix.pending, s.hash)
				ix.mu.Unlock()
				continue
			}
			errs = append(errs, err)
			continue
		}
		text, err := ix.text(b)
		clear(b)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := ix.Add(ctx, s.subject, s.hash, text); err != nil && !errors.Is(err, ErrFull) {
			if errors.Is(err, ErrUnavailable) {
				return errors.Join(append(errs, err)...)
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (ix *Index) text(b []byte) (string, error) {
	if ix.Text != nil {
		return ix.Text(b)
	}
	return string(b), nil
}

// Stats reports the index's counts.
func (ix *Index) Stats() Stats {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return Stats{
		Items: len(ix.items), Chunks: len(ix.entries), Cap: ix.cap,
		Pending: len(ix.pending), Full: ix.full, UnindexedBytes: ix.overflow,
		Skipped: ix.skipped, Stale: ix.stale,
	}
}

// causeOf names an embed error by its type only: an error's text may
// carry what the service said, which this package does not log.
func causeOf(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	}
	return "service error"
}
