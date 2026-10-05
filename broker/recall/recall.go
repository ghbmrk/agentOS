package recall

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Label is an item's data label (REV-5). Anything other than Public is
// treated as Private, so a missing or misspelt label fails closed.
type Label string

const (
	Public  Label = "public"
	Private Label = "private"
)

// publicKinds are the only source kinds that may be public, and only when
// the caller declares exactly Public (REV-5). web: an uncredentialed fetch
// (a credentialed read is kind "credentialed", set by the executor). timer
// and task: task text the owner marked PUBLIC (D1). agent: output of a
// machine the broker labelled public. Every other kind, including new or
// misspelt ones, is private.
var publicKinds = map[string]bool{"web": true, "timer": true, "task": true, "agent": true}

// EffectiveLabel is the label an item or event of this kind gets when its
// producer declares declared. The recall index and the event bus share it.
func EffectiveLabel(kind string, declared Label) Label {
	if declared == Public && publicKinds[kind] {
		return Public
	}
	return Private
}

// ReservedKinds are kinds only the broker's owner channel may produce.
// Ingest refuses "preference" (preferences have their own write path) and
// the event bus refuses both.
var ReservedKinds = map[string]bool{"owner": true, "preference": true}

// Source is an item's provenance (CAP-3).
type Source struct {
	// Kind is where the item came from: mail, file, calendar, contact, web,
	// timer, task, agent, owner, credentialed (an executor read), ...
	Kind    string `json:"kind"`
	Account string `json:"account,omitempty"`
	// Ref names the item in its origin (message ID, path, URL, task ID).
	// It is stored and shown scrubbed; identity uses the raw ref, keyed.
	Ref  string    `json:"ref"`
	Seen time.Time `json:"seen"`
	// DerivedFrom lists the item IDs this one was computed from (a summary,
	// extracted facts). Deleting a parent deletes it too.
	DerivedFrom []string `json:"derived_from,omitempty"`
}

// Fact is a structured statement extracted from an item.
type Fact struct {
	Subject   string `json:"s"`
	Predicate string `json:"p"`
	Object    string `json:"o"`
}

// Item is one indexed thing the system has seen.
type Item struct {
	ID     string    `json:"id"`
	Source Source    `json:"source"`
	Label  Label     `json:"label"`
	Text   string    `json:"text,omitempty"`
	Facts  []Fact    `json:"facts,omitempty"`
	Vector []float32 `json:"vec,omitempty"`
	VecID  string    `json:"vec_id,omitempty"` // Embedder.ID of Vector
	// Received is when the broker received this content, on the broker's
	// clock (the event bus passes its publish time; a direct caller passes
	// when it fetched the content). It decides staleness against
	// tombstones; Source.Seen is the source's own time and is for display
	// only. Zero means unknown: stored as now, but refused for a deleted
	// source. A future time is refused.
	Received time.Time `json:"received,omitempty"`
	// LabelBy is the owner-channel message that lowered the label, if one
	// did (Relabel). Empty for labels set at ingest.
	LabelBy string `json:"label_by,omitempty"`
}

// OwnerMessage is an authenticated owner-channel message (owner text or
// local UI action), the only provenance a preference or a lowered label may
// have. The owner channel parses the message into the action it asks for
// and that action's target; a message authorizes exactly that action on
// exactly that target, once.
type OwnerMessage struct {
	ID      string    `json:"id"`
	Channel string    `json:"channel"` // "sms", "voice", "local-ui"
	At      time.Time `json:"at"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
}

// Owner actions a message can authorize here.
const (
	ActionPublic     = "recall.public"     // target: item ID (D1 PUBLIC opt-out, local-UI relabel)
	ActionPrefSet    = "preference.set"    // target: preference key
	ActionPrefDelete = "preference.delete" // target: preference key
)

// OwnerAuth looks up a message the broker's owner channel authenticated.
// It returns false for anything else: mail, agent output, unknown IDs.
type OwnerAuth func(messageID string) (OwnerMessage, bool)

// Preference is an owner correction stored as an explicit, editable rule.
type Preference struct {
	Key        string       `json:"key"`
	Value      string       `json:"value"`
	Provenance OwnerMessage `json:"provenance"`
}

// Labeler reads and raises agent machines' data labels (REV-5). Raise must
// have taken effect (egress narrowed) before it returns nil.
type Labeler interface {
	Label(machine string) Label
	Raise(machine string) error
}

// Keyer derives identities from raw source names with a broker key
// (HMAC-SHA256), so identity survives scrubbing of the displayed ref, refs
// that scrub alike stay distinct, and a stored ID does not reveal a
// low-entropy raw ref to someone without the key.
type Keyer struct{ key []byte }

// NewKeyer returns a Keyer for key (at least 16 bytes).
func NewKeyer(key []byte) (Keyer, error) {
	if len(key) < 16 {
		return Keyer{}, errors.New("recall: identity key must be at least 16 bytes")
	}
	return Keyer{key: append([]byte(nil), key...)}, nil
}

// ID hashes length-prefixed parts.
func (k Keyer) ID(parts ...string) string {
	m := hmac.New(sha256.New, k.key)
	var n [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		m.Write(n[:])
		m.Write([]byte(p))
	}
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// SourceID is the identity of the item for a raw source name. The event
// bus uses the same identity, so a deletion reaches its copy.
func (k Keyer) SourceID(kind, account, rawRef string) string {
	return k.ID("src", kind, account, rawRef)
}

// Valid reports whether the keyer has a key.
func (k Keyer) Valid() bool { return len(k.key) >= 16 }

// Deleted is passed to OnDelete hooks. Source is empty when the item was
// never indexed here (a deletion that arrived first) or is a replayed
// tombstone.
type Deleted struct {
	ID     string
	Source Source
}

var (
	ErrNoSource     = errors.New("recall: item needs a source kind and ref")
	ErrReservedKind = errors.New("recall: reserved source kind")
	ErrDeleted      = errors.New("recall: source was deleted; refusing content received before the deletion")
	ErrFuture       = errors.New("recall: receipt time is in the future")
	ErrUsedMessage  = errors.New("recall: this owner message was already used")
	ErrNotOwner     = errors.New("recall: needs an authenticated owner-channel message for this action and target")
	ErrNoLabeler    = errors.New("recall: private results need a labeler to raise the caller (REV-5)")
	ErrUnknownPref  = errors.New("recall: no such preference")
)

// Index is the broker-owned recall index (CAP-3): full text, embeddings and
// structured facts over everything the system has seen, with provenance.
// Agents reach it only through Search and PreferencesFor, which raise the
// caller's label before returning owner data, and see results only through
// Render (untrusted content, no scores). Only the broker writes to it.
//
// Memory holds what search needs (postings, quantized vectors, facts,
// labels); item text and provenance stay in the segments on disk and are
// read for the results returned (R8).
type Index struct {
	mu       sync.RWMutex
	dir      Dir
	meta     Store
	scrub    *Scrubber
	emb      Embedder
	labels   Labeler
	owner    OwnerAuth
	now      func() time.Time
	keyer    Keyer
	keyGiven bool
	hdrEmb   string

	items    map[string]*entry
	byDoc    map[uint32]*entry
	children map[string][]string // parent ID -> IDs derived from it
	older    map[string][]uint32 // ID -> segments still holding superseded versions
	all      *textIndex          // every item
	pub      *textIndex          // public items only: public-only searches rank here
	nextDoc  uint32

	segs     map[uint32]*segInfo
	active   uint32
	dirty    map[uint32]bool      // segments that lost live lines since the last check
	unerased map[uint32]bool      // segments a failed rewrite left holding deleted data
	keepTomb func(id string) bool // tombstones PruneTombstones must keep

	prefs     map[string]Preference
	tombs     map[string]time.Time // deleted ID -> deletion time
	used      map[string]bool      // owner message IDs already acted on
	onDelete  []func(Deleted) error
	metaLines int
	skipped   int
}

// Option configures an Index.
type Option func(*Index)

// WithEmbedder sets the embedder (default HashEmbedder). Nil disables vectors.
func WithEmbedder(e Embedder) Option { return func(ix *Index) { ix.emb = e } }

// WithLabeler sets the machine-label source used by Search.
func WithLabeler(l Labeler) Option { return func(ix *Index) { ix.labels = l } }

// WithOwnerAuth sets the owner-channel authenticator for preferences.
func WithOwnerAuth(a OwnerAuth) Option { return func(ix *Index) { ix.owner = a } }

// WithVaultRedactor adds the vault's redactor (CRED-7) ahead of the
// pattern scrubber.
func WithVaultRedactor(r func(string) string) Option {
	return func(ix *Index) { ix.scrub = NewScrubber(r) }
}

// WithKeyer sets the identity key, normally a vault-held broker key. Without
// it a random key is generated on first open and kept in the meta header.
func WithKeyer(k Keyer) Option {
	return func(ix *Index) { ix.keyer, ix.keyGiven = k, k.Valid() }
}

// WithClock sets the clock.
func WithClock(now func() time.Time) Option { return func(ix *Index) { ix.now = now } }

type header struct {
	Key      string `json:"key,omitempty"` // hex; only when generated here
	Embedder string `json:"embedder,omitempty"`
}

// record is a meta-log record.
type record struct {
	Op     string      `json:"op"` // "hdr", "pref", "tomb", "used"
	Header *header     `json:"hdr,omitempty"`
	Pref   *Preference `json:"pref,omitempty"`
	ID     string      `json:"id,omitempty"`
	At     time.Time   `json:"at,omitempty"`
}

// Open loads the index from d. Unreadable records are skipped (and counted
// by Skipped) and rewritten away, and so is any content a deletion that a
// crash cut off had not yet erased.
func Open(d Dir, opts ...Option) (*Index, error) {
	ix := &Index{
		dir:      d,
		meta:     d.Meta(),
		scrub:    NewScrubber(nil),
		emb:      HashEmbedder{},
		now:      func() time.Time { return time.Now().UTC() },
		items:    map[string]*entry{},
		byDoc:    map[uint32]*entry{},
		children: map[string][]string{},
		older:    map[string][]uint32{},
		all:      newTextIndex(),
		pub:      newTextIndex(),
		segs:     map[uint32]*segInfo{},
		dirty:    map[uint32]bool{},
		unerased: map[uint32]bool{},
		prefs:    map[string]Preference{},
		tombs:    map[string]time.Time{},
		used:     map[string]bool{},
	}
	for _, o := range opts {
		o(ix)
	}
	rewriteMeta, err := ix.loadMeta()
	if err != nil {
		return nil, err
	}
	if !ix.keyer.Valid() {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		ix.keyer = Keyer{key: key}
		rewriteMeta = true
	}
	if ix.hdrEmb != ix.embID() {
		rewriteMeta = true
	}
	if rewriteMeta {
		if err := ix.compactMeta(); err != nil {
			return nil, err
		}
	}
	if err := ix.loadSegments(); err != nil {
		return nil, err
	}
	return ix, nil
}

// Skipped returns how many unreadable records Open dropped.
func (ix *Index) Skipped() int { return ix.skipped }

// Keyer returns the identity keyer, for the event bus.
func (ix *Index) Keyer() Keyer { return ix.keyer }

// SourceID is the item ID for a raw source name.
func (ix *Index) SourceID(kind, account, rawRef string) string {
	return ix.keyer.SourceID(kind, account, rawRef)
}

func (ix *Index) embID() string {
	if ix.emb == nil {
		return ""
	}
	return ix.emb.ID()
}

func (ix *Index) minCosine() float64 {
	if f, ok := ix.emb.(CosineFloor); ok {
		return f.MinCosine()
	}
	return defaultMinCosine
}

// Ingest indexes an item, replacing any earlier item from the same source.
// The ID is the keyed identity of the raw ref; text, facts and the displayed
// ref are scrubbed of credentials first (CRED-1). Ingest never creates a
// preference, whatever the text says (CAP-3).
func (ix *Index) Ingest(it Item) (string, error) {
	if it.Source.Kind == "" || it.Source.Ref == "" {
		return "", ErrNoSource
	}
	return ix.IngestKeyed(ix.SourceID(it.Source.Kind, it.Source.Account, it.Source.Ref), it)
}

// IngestKeyed is Ingest with an identity already computed by this index's
// Keyer from the raw ref (the event bus passes it, since it stores only the
// scrubbed ref).
func (ix *Index) IngestKeyed(id string, it Item) (string, error) {
	ids, errs := ix.ingest([]string{id}, []Item{it})
	return ids[0], errs[0]
}

// IngestBatch ingests items with one durable write per segment rather than
// one per item, for backfills (a mailbox's history). Each item is admitted
// or refused exactly as by Ingest; ids[i] and errs[i] are item i's outcome.
func (ix *Index) IngestBatch(items []Item) (ids []string, errs []error) {
	keys := make([]string, len(items))
	for i, it := range items {
		if it.Source.Kind != "" && it.Source.Ref != "" {
			keys[i] = ix.SourceID(it.Source.Kind, it.Source.Account, it.Source.Ref)
		}
	}
	return ix.ingest(keys, items)
}

// pendingPut is an admitted item and whether its receipt time was unknown.
type pendingPut struct {
	i       int
	it      Item
	unknown bool
}

func (ix *Index) ingest(keys []string, items []Item) ([]string, []error) {
	ids := make([]string, len(items))
	errs := make([]error, len(items))
	now := ix.now()
	var ready []pendingPut
	for i, it := range items {
		p, err := ix.prepare(keys[i], it, now)
		if err != nil {
			errs[i] = err
			continue
		}
		ready = append(ready, p)
		ready[len(ready)-1].i = i
	}

	ix.mu.Lock()
	defer ix.mu.Unlock()
	var batch []*Item
	var idx []int
	inBatch := map[string]bool{}
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Items before a failed append are durable and indexed: report
		// them as ingested, and the error only for the rest. A compaction
		// failure after all are applied is retried by later writes.
		n, err := ix.putLockedN(batch)
		for k, i := range idx {
			if k < n {
				ids[i] = batch[k].ID
			} else {
				errs[i] = err
			}
		}
		batch, idx, inBatch = nil, nil, map[string]bool{}
	}
	for _, p := range ready {
		// An item whose identity or a parent is earlier in this batch is
		// admitted against the stored state, so the earlier one goes first.
		dep := inBatch[p.it.ID]
		for _, par := range p.it.Source.DerivedFrom {
			dep = dep || inBatch[par]
		}
		if dep {
			flush()
		}
		it := p.it
		if err := ix.admitLocked(&it, p.unknown); err != nil {
			errs[p.i] = err
			continue
		}
		batch = append(batch, &it)
		idx = append(idx, p.i)
		inBatch[it.ID] = true
	}
	flush()
	return ids, errs
}

// prepare checks and scrubs an item and embeds it, outside the lock.
func (ix *Index) prepare(id string, it Item, now time.Time) (pendingPut, error) {
	if it.Source.Kind == "" || it.Source.Ref == "" || id == "" {
		return pendingPut{}, ErrNoSource
	}
	if it.Source.Kind == "preference" {
		return pendingPut{}, fmt.Errorf("%w: %s", ErrReservedKind, it.Source.Kind)
	}
	it.ID = id
	it.Label = EffectiveLabel(it.Source.Kind, it.Label)
	it.LabelBy = ""
	unknown := it.Received.IsZero()
	if unknown {
		it.Received = now
	}
	if it.Received.After(now) {
		return pendingPut{}, ErrFuture
	}
	if it.Source.Seen.IsZero() {
		it.Source.Seen = it.Received
	}
	it.Source.Ref = ix.scrub.Scrub(it.Source.Ref)
	it.Text = ix.scrub.Scrub(it.Text)
	facts := make([]Fact, 0, len(it.Facts))
	for _, f := range it.Facts {
		facts = append(facts, Fact{ix.scrub.Scrub(f.Subject), ix.scrub.Scrub(f.Predicate), ix.scrub.Scrub(f.Object)})
	}
	it.Facts = facts
	it.Source.DerivedFrom = append([]string(nil), it.Source.DerivedFrom...)
	it.Vector, it.VecID = nil, ""
	if ix.emb != nil {
		if vs, err := ix.emb.Embed([]string{searchText(&it)}); err == nil && len(vs) == 1 {
			it.Vector, it.VecID = vs[0], ix.emb.ID()
		}
	}
	return pendingPut{it: it, unknown: unknown}, nil
}

// admitLocked applies the rules that depend on stored state. Caller holds mu.
func (ix *Index) admitLocked(it *Item, unknownReceipt bool) error {
	// Content the broker received before a deletion of this source never
	// comes back (a stale delivery racing the deletion). Receipt time is the
	// broker's own, so a source cannot date its way past a tombstone.
	// An unknown receipt time counts as stale against a tombstone.
	if t, ok := ix.tombs[it.ID]; ok && (unknownReceipt || !it.Received.After(t)) {
		return ErrDeleted
	}
	// A label never falls on re-ingest; only Relabel lowers one. An owner
	// relabel to public carries over while the caller still declares public.
	if old := ix.items[it.ID]; old != nil {
		switch {
		case old.label == Private:
			it.Label = Private
		case old.labelBy != "" && it.Label == Public:
			it.LabelBy = old.labelBy
		}
	}
	// Nothing derived from a deleted item comes in while its tombstone
	// stands, so a deletion cannot be laundered through a note made from
	// it (CAP-3). A parent ingested again after its deletion is live and
	// counts as itself.
	for _, p := range it.Source.DerivedFrom {
		if _, gone := ix.tombs[p]; gone && ix.items[p] == nil {
			return ErrDeleted
		}
	}
	// A derived item is at least as private as its parents, and private if
	// any parent is unknown here.
	for _, p := range it.Source.DerivedFrom {
		if pi := ix.items[p]; pi == nil || pi.label == Private {
			it.Label = Private
		}
	}
	return nil
}

func searchText(it *Item) string {
	var b strings.Builder
	b.WriteString(it.Text)
	for _, f := range it.Facts {
		b.WriteString("\n")
		b.WriteString(f.Subject + " " + f.Predicate + " " + f.Object)
	}
	return b.String()
}

// Get returns an item (broker side).
func (ix *Index) Get(id string) (Item, bool) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	e, ok := ix.items[id]
	if !ok {
		return Item{}, false
	}
	it, err := ix.readItem(e)
	if err != nil {
		return Item{}, false
	}
	return it, true
}

// Len returns the number of items.
func (ix *Index) Len() int {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return len(ix.items)
}

// Reembed re-embeds up to limit items whose vectors are from another
// embedder (or missing) and returns how many it did. The broker runs it in
// the background after the embedder changes; until then those items match
// by text and facts only.
func (ix *Index) Reembed(limit int) (int, error) {
	if ix.emb == nil {
		return 0, nil
	}
	want := ix.emb.ID()
	ix.mu.RLock()
	var stale []string
	for id, e := range ix.items {
		if e.vecID != want {
			stale = append(stale, id)
			if len(stale) >= limit {
				break
			}
		}
	}
	ix.mu.RUnlock()
	n := 0
	for _, id := range stale {
		ix.mu.RLock()
		e := ix.items[id]
		var it Item
		var err error
		if e != nil {
			it, err = ix.readItem(e)
		}
		ix.mu.RUnlock()
		if e == nil {
			continue
		}
		if err != nil {
			return n, err
		}
		vs, err := ix.emb.Embed([]string{searchText(&it)})
		if err != nil || len(vs) != 1 {
			return n, err
		}
		ix.mu.Lock()
		// Only the version that was read: a newer one has its own vector.
		if cur := ix.items[id]; cur == e && cur.vecID != want {
			it.Vector, it.VecID = vs[0], want
			if err := ix.putLocked([]*Item{&it}); err != nil {
				ix.mu.Unlock()
				return n, err
			}
			n++
		}
		ix.mu.Unlock()
	}
	return n, nil
}

// DeleteReport lists what a deletion removed.
type DeleteReport struct {
	Items   []string
	Sources []Source
}

// OnDelete registers a hook called for every deleted ID after the deletion
// is durable, so other stores (the event bus, caches) drop their copies
// (CAP-3: deletion requests propagate). On registration it is called once
// for every tombstone already recorded, so a deletion that a crash cut off
// before its hooks ran still arrives.
func (ix *Index) OnDelete(f func(Deleted) error) error {
	ix.mu.Lock()
	ix.onDelete = append(ix.onDelete, f)
	ids := make([]string, 0, len(ix.tombs))
	for id := range ix.tombs {
		ids = append(ids, id)
	}
	ix.mu.Unlock()
	sort.Strings(ids)
	var errs []error
	for _, id := range ids {
		if err := f(Deleted{ID: id}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// DeleteSource deletes the item for a raw source name, whether or not it
// has been indexed yet.
func (ix *Index) DeleteSource(kind, account, rawRef string) (DeleteReport, error) {
	return ix.Delete(ix.SourceID(kind, account, rawRef))
}

// Delete removes items and every item derived from them (transitively),
// with their facts and vectors. It records a durable tombstone for each
// requested and removed ID first, then rewrites the segments that held any
// version of them so no copy remains in a live file, and then calls the
// OnDelete hooks for each of those IDs, including requested IDs that were
// not indexed (the event bus may still hold them). Once the tombstones are
// durable the deletion has taken effect: if a segment rewrite fails, the
// error is returned, the rewrite is retried on the next deletion, and
// Open erases what is left. Hook errors are returned likewise.
func (ix *Index) Delete(ids ...string) (DeleteReport, error) {
	ix.mu.Lock()
	gone := map[string]bool{}
	var queue []string
	for _, id := range ids {
		if id != "" && !gone[id] {
			gone[id] = true
			queue = append(queue, id)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range ix.children[cur] {
			if !gone[c] {
				gone[c] = true
				queue = append(queue, c)
			}
		}
	}
	all := make([]string, 0, len(gone))
	for id := range gone {
		all = append(all, id)
	}
	sort.Strings(all)
	removed := map[string]Item{}
	for _, id := range all {
		if e := ix.items[id]; e != nil {
			// An unreadable item is still deleted: its tombstone is
			// written, its segment rewritten without it, and its source
			// reported empty.
			it, _ := ix.readItem(e)
			removed[id] = it
		}
	}
	now := ix.now()
	var buf []byte
	for _, id := range all {
		b, err := json.Marshal(record{Op: "tomb", ID: id, At: now})
		if err != nil {
			ix.mu.Unlock()
			return DeleteReport{}, err
		}
		buf = append(append(buf, b...), '\n')
	}
	if err := ix.meta.Append(buf); err != nil {
		ix.mu.Unlock()
		return DeleteReport{}, err
	}
	ix.metaLines += len(all)
	erase := map[uint32]bool{}
	for n := range ix.unerased {
		erase[n] = true
	}
	var rep DeleteReport
	srcs := map[string]Source{}
	for _, id := range all {
		ix.tombs[id] = now
		if e := ix.items[id]; e != nil {
			it := removed[id]
			erase[e.seg] = true
			ix.dropLocked(e, searchText(&it), false)
			rep.Items = append(rep.Items, id)
			rep.Sources = append(rep.Sources, it.Source)
			srcs[id] = it.Source
		}
		for _, n := range ix.older[id] {
			erase[n] = true
		}
		delete(ix.older, id)
	}
	errErase := ix.rewriteSegs(erase)
	errMeta := ix.maybeCompactMeta()
	hooks := append([]func(Deleted) error{}, ix.onDelete...)
	ix.mu.Unlock()
	errs := []error{errErase, errMeta}
	for _, id := range all {
		for _, h := range hooks {
			if err := h(Deleted{ID: id, Source: srcs[id]}); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return rep, errors.Join(errs...)
}

// ErrNotRelabelable means the item's kind or parents cannot be public.
var ErrNotRelabelable = errors.New("recall: this item cannot be public")

// Relabel changes an item's label. Raising to private is always allowed and
// needs no message. Lowering to public is the only path that lowers a label
// (REV-5): it needs an authenticated owner-channel message whose action is
// ActionPublic and whose target is this item (the D1 PUBLIC opt-out for that
// task, or a relabel of that item on the local UI). Each message is used at
// most once, so it cannot be replayed after the owner raises the item again.
// The message is recorded on the item as LabelBy. Lowering is refused for
// kinds that can never be public and for items with a private or unknown
// parent. The broker journals it as a broker-state intent (OP-5; a wiring
// condition) before calling this.
func (ix *Index) Relabel(messageID, id string, l Label) error {
	var msg OwnerMessage
	if l == Public {
		var err error
		if msg, err = ix.ownerMessage(messageID, ActionPublic, id); err != nil {
			return err
		}
	} else {
		l = Private
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	cur := ix.items[id]
	if cur == nil {
		return fmt.Errorf("recall: no item %s", id)
	}
	if l == Public {
		if ix.used[msg.ID] {
			return ErrUsedMessage
		}
		if !publicKinds[cur.kind] {
			return ErrNotRelabelable
		}
		for _, p := range cur.derived {
			if pi := ix.items[p]; pi == nil || pi.label != Public {
				return ErrNotRelabelable
			}
		}
		if err := ix.appendMeta(record{Op: "used", ID: msg.ID}); err != nil {
			return err
		}
		ix.used[msg.ID] = true
	}
	up, err := ix.readItem(cur)
	if err != nil {
		return err
	}
	up.Label, up.LabelBy = l, msg.ID
	puts := []*Item{&up}
	if l == Private {
		// Raise everything derived from it too, transitively.
		seen := map[string]bool{id: true}
		queue := append([]string(nil), ix.children[id]...)
		for len(queue) > 0 {
			c := queue[0]
			queue = queue[1:]
			if seen[c] {
				continue
			}
			seen[c] = true
			queue = append(queue, ix.children[c]...)
			e := ix.items[c]
			if e == nil || e.label != Public {
				continue
			}
			d, err := ix.readItem(e)
			if err != nil {
				return err
			}
			d.Label, d.LabelBy = Private, ""
			puts = append(puts, &d)
		}
	}
	return ix.putLocked(puts)
}

// SetPreference stores or replaces an owner preference. messageID must name
// a message the owner channel authenticated; it becomes the provenance.
func (ix *Index) SetPreference(messageID, key, value string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("recall: preference key is empty")
	}
	msg, err := ix.ownerMessage(messageID, ActionPrefSet, key)
	if err != nil {
		return err
	}
	p := Preference{Key: key, Value: ix.scrub.Scrub(value), Provenance: msg}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if ix.used[msg.ID] {
		return ErrUsedMessage
	}
	old, had := ix.prefs[key]
	ix.prefs[key] = p
	ix.used[msg.ID] = true
	// Rewrite so an edited value leaves no earlier copy in the store.
	if err := ix.compactMeta(); err != nil {
		delete(ix.used, msg.ID)
		if had {
			ix.prefs[key] = old
		} else {
			delete(ix.prefs, key)
		}
		return err
	}
	return nil
}

// DeletePreference removes an owner preference, on an authenticated owner
// message.
func (ix *Index) DeletePreference(messageID, key string) error {
	msg, err := ix.ownerMessage(messageID, ActionPrefDelete, key)
	if err != nil {
		return err
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if ix.used[msg.ID] {
		return ErrUsedMessage
	}
	old, ok := ix.prefs[key]
	if !ok {
		return ErrUnknownPref
	}
	delete(ix.prefs, key)
	ix.used[msg.ID] = true
	if err := ix.compactMeta(); err != nil {
		delete(ix.used, msg.ID)
		ix.prefs[key] = old
		return err
	}
	return nil
}

// ownerMessage checks that id is an authenticated owner message asking for
// exactly this action on exactly this target. Single use is checked by the
// caller under the lock.
func (ix *Index) ownerMessage(id, action, target string) (OwnerMessage, error) {
	if ix.owner == nil || id == "" {
		return OwnerMessage{}, ErrNotOwner
	}
	msg, ok := ix.owner(id)
	if !ok || msg.ID != id || msg.Action != action || msg.Target != target {
		return OwnerMessage{}, ErrNotOwner
	}
	return msg, nil
}

// MinTombstoneAge is the floor for PruneTombstones.
const MinTombstoneAge = 24 * time.Hour

// PruneTombstones drops tombstones older than maxAge and returns how many.
// A tombstone only has to outlive deliveries already in flight when the
// deletion happened (the bus gives up after its tries, within minutes) and
// the hooks' replay after a crash; the broker prunes with a margin of days
// (default policy: 30 days). Nothing is pruned while a deleted item's
// content still waits to be erased from a segment, since the tombstone is
// what keeps it from coming back.
func (ix *Index) PruneTombstones(maxAge time.Duration) (int, error) {
	if maxAge < MinTombstoneAge {
		return 0, fmt.Errorf("recall: tombstones must be kept at least %v", MinTombstoneAge)
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if len(ix.unerased) > 0 {
		retry := map[uint32]bool{}
		for n := range ix.unerased {
			retry[n] = true
		}
		if err := ix.rewriteSegs(retry); err != nil {
			return 0, err
		}
	}
	cut := ix.now().Add(-maxAge)
	old := map[string]time.Time{}
	for id, t := range ix.tombs {
		if t.Before(cut) && (ix.keepTomb == nil || !ix.keepTomb(id)) {
			old[id] = t
			delete(ix.tombs, id)
		}
	}
	if len(old) == 0 {
		return 0, nil
	}
	if err := ix.compactMeta(); err != nil {
		for id, t := range old {
			ix.tombs[id] = t
		}
		return 0, err
	}
	return len(old), nil
}

// KeepTombstones makes PruneTombstones keep any tombstone keep reports
// as still needed, whatever its age: recall's deletion reach keeps one
// while an agent lineage still holds the deleted item (recalltool W10).
func (ix *Index) KeepTombstones(keep func(id string) bool) {
	ix.mu.Lock()
	ix.keepTomb = keep
	ix.mu.Unlock()
}

// Preferences returns all preferences, sorted by key (broker side).
func (ix *Index) Preferences() []Preference {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	out := make([]Preference, 0, len(ix.prefs))
	for _, p := range ix.prefs {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// PreferencesFor returns the preferences for delivery to an agent machine.
// They are owner data, so the machine is raised to private first (REV-5),
// whether or not any exist, so the answer reveals nothing to a public one.
func (ix *Index) PreferencesFor(machine string) ([]Preference, error) {
	if err := ix.raise(machine); err != nil {
		return nil, err
	}
	return ix.Preferences(), nil
}

func (ix *Index) raise(machine string) error {
	if ix.labels == nil {
		return ErrNoLabeler
	}
	if ix.labels.Label(machine) == Private {
		return nil
	}
	if err := ix.labels.Raise(machine); err != nil {
		return fmt.Errorf("recall: raising %s to private: %w", machine, err)
	}
	if ix.labels.Label(machine) != Private {
		return fmt.Errorf("recall: %s is still not private after raise", machine)
	}
	return nil
}

// FactPattern matches facts; empty fields match anything. Matching is
// case-insensitive.
type FactPattern struct {
	Subject, Predicate, Object string
}

func (p FactPattern) match(f Fact) bool {
	eq := func(want, got string) bool { return want == "" || strings.EqualFold(want, got) }
	return eq(p.Subject, f.Subject) && eq(p.Predicate, f.Predicate) && eq(p.Object, f.Object)
}

// Query is a recall search.
type Query struct {
	Text  string
	Fact  *FactPattern
	Kinds []string // source kinds to include; empty means all
	Limit int      // default 10, at most 100
	// PublicOnly searches public items only, ranked on public items only, so
	// neither the results nor their order depend on private data, and the
	// caller is not raised.
	PublicOnly bool
}

// Result is one search hit. Score is broker-side only: Search zeroes it and
// Render never shows it.
type Result struct {
	ID     string
	Source Source
	Label  Label
	Text   string
	Facts  []Fact
	Score  float64
}

// Lookup searches on the broker's or owner's behalf. It changes no label.
func (ix *Index) Lookup(q Query) []Result {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.search(q)
}

// Search searches on behalf of an agent machine (REV-5). A PublicOnly query
// reads only public items and public statistics and leaves the machine's
// label alone. Any other query raises the machine to private before it is
// run, whatever it finds, since even "nothing matched" is owner data; if the
// raise fails, nothing is returned. Deliver results to the agent only
// through Render (CAP-3: untrusted content, never instructions).
func (ix *Index) Search(machine string, q Query) ([]Result, error) {
	if !q.PublicOnly {
		if err := ix.raise(machine); err != nil {
			return nil, err
		}
	}
	rs := ix.Lookup(q)
	for i := range rs {
		rs[i].Score = 0
	}
	return rs, nil
}

func (ix *Index) search(q Query) []Result {
	limit := q.Limit
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}
	kinds := map[string]bool{}
	for _, k := range q.Kinds {
		kinds[k] = true
	}
	eligible := func(e *entry) bool {
		if e == nil {
			return false
		}
		if q.PublicOnly && e.label != Public {
			return false
		}
		if len(kinds) > 0 && !kinds[e.kind] {
			return false
		}
		if q.Fact != nil {
			for _, f := range e.facts {
				if q.Fact.match(f) {
					return true
				}
			}
			return false
		}
		return true
	}

	type cand struct {
		e     *entry
		score float64
	}
	var cands []cand
	if strings.TrimSpace(q.Text) == "" {
		if q.Fact == nil {
			return nil
		}
		for _, e := range ix.items {
			if eligible(e) {
				cands = append(cands, cand{e, 1})
			}
		}
	} else {
		text := ix.all
		if q.PublicOnly {
			text = ix.pub
		}
		bm := text.score(q.Text)
		var max float64
		for doc, s := range bm {
			if s > max && eligible(ix.byDoc[doc]) {
				max = s
			}
		}
		var qv []float32
		var qn float64
		embID := ix.embID()
		if ix.emb != nil {
			if vs, err := ix.emb.Embed([]string{q.Text}); err == nil && len(vs) == 1 {
				qv, qn = vs[0], norm(vs[0])
			}
		}
		floor := ix.minCosine()
		for _, e := range ix.items {
			if !eligible(e) {
				continue
			}
			var s float64
			if b := bm[e.doc]; b > 0 && max > 0 {
				s += 0.6 * b / max
			}
			if qv != nil && e.vecID == embID {
				if c := cosineQ(qv, qn, e.vec, e.vnorm); c >= floor {
					s += 0.4 * c
				}
			}
			if s > 0 {
				cands = append(cands, cand{e, s})
			}
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.score != b.score {
			return a.score > b.score
		}
		if !a.e.seen.Equal(b.e.seen) {
			return a.e.seen.After(b.e.seen)
		}
		return a.e.id < b.e.id
	})
	out := make([]Result, 0, limit)
	for _, c := range cands {
		if len(out) == limit {
			break
		}
		it, err := ix.readItem(c.e)
		if err != nil {
			continue // unreadable on the medium: not served
		}
		out = append(out, Result{ID: it.ID, Source: it.Source, Label: c.e.label, Text: it.Text,
			Facts: append([]Fact(nil), it.Facts...), Score: c.score})
	}
	return out
}
