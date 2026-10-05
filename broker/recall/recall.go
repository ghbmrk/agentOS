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
type Index struct {
	mu       sync.RWMutex
	store    Store
	scrub    *Scrubber
	emb      Embedder
	labels   Labeler
	owner    OwnerAuth
	now      func() time.Time
	keyer    Keyer
	keyGiven bool
	hdrEmb   string
	items    map[string]*Item
	all      *textIndex // every item
	pub      *textIndex // public items only: public-only searches rank here
	prefs    map[string]Preference
	tombs    map[string]time.Time // deleted ID -> deletion time
	used     map[string]bool      // owner message IDs already acted on
	onDelete []func(Deleted) error
	lines    int // records in the store
	skipped  int
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
// it a random key is generated on first open and kept in the store header.
func WithKeyer(k Keyer) Option {
	return func(ix *Index) { ix.keyer, ix.keyGiven = k, k.Valid() }
}

// WithClock sets the clock.
func WithClock(now func() time.Time) Option { return func(ix *Index) { ix.now = now } }

type header struct {
	Key      string `json:"key,omitempty"` // hex; only when generated here
	Embedder string `json:"embedder,omitempty"`
}

type record struct {
	Op     string      `json:"op"` // "hdr", "put", "pref", "tomb"
	Header *header     `json:"hdr,omitempty"`
	Item   *Item       `json:"item,omitempty"`
	Pref   *Preference `json:"pref,omitempty"`
	ID     string      `json:"id,omitempty"`
	At     time.Time   `json:"at,omitempty"`
}

// Open loads the index from store. An unreadable record is skipped (and
// counted by Skipped), and the store is rewritten without it.
func Open(store Store, opts ...Option) (*Index, error) {
	ix := &Index{
		store: store,
		scrub: NewScrubber(nil),
		emb:   HashEmbedder{},
		now:   func() time.Time { return time.Now().UTC() },
		items: map[string]*Item{},
		all:   newTextIndex(),
		pub:   newTextIndex(),
		prefs: map[string]Preference{},
		tombs: map[string]time.Time{},
		used:  map[string]bool{},
	}
	for _, o := range opts {
		o(ix)
	}
	data, err := store.ReadAll()
	if err != nil {
		return nil, err
	}
	lines, torn := Lines(data)
	for _, l := range lines {
		var r record
		if err := json.Unmarshal(l, &r); err != nil {
			ix.skipped++
			continue
		}
		ix.apply(r)
	}
	ix.lines = len(lines)
	if !ix.keyer.Valid() {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		ix.keyer = Keyer{key: key}
		torn = true // write the header
	}
	if ix.hdrEmb != ix.embID() {
		torn = true
	}
	if torn || ix.skipped > 0 {
		if err := ix.compact(); err != nil {
			return nil, err
		}
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
	if it.Source.Kind == "" || it.Source.Ref == "" || id == "" {
		return "", ErrNoSource
	}
	if it.Source.Kind == "preference" {
		return "", fmt.Errorf("%w: %s", ErrReservedKind, it.Source.Kind)
	}
	it.ID = id
	it.Label = EffectiveLabel(it.Source.Kind, it.Label)
	now := ix.now()
	unknownReceipt := it.Received.IsZero()
	if unknownReceipt {
		it.Received = now
	}
	if it.Received.After(now) {
		return "", ErrFuture
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

	ix.mu.Lock()
	defer ix.mu.Unlock()
	// Content the broker received before a deletion of this source never
	// comes back (a stale delivery racing the deletion). Receipt time is the
	// broker's own, so a source cannot date its way past a tombstone.
	// An unknown receipt time counts as stale against a tombstone.
	if t, ok := ix.tombs[id]; ok && (unknownReceipt || !it.Received.After(t)) {
		return "", ErrDeleted
	}
	// A label never falls on re-ingest; only Relabel lowers one. An owner
	// relabel to public carries over while the caller still declares public.
	if old := ix.items[id]; old != nil {
		switch {
		case old.Label == Private:
			it.Label = Private
		case old.LabelBy != "" && it.Label == Public:
			it.LabelBy = old.LabelBy
		}
	}
	// A derived item is at least as private as its parents, and private if
	// any parent is unknown here.
	for _, p := range it.Source.DerivedFrom {
		if pi := ix.items[p]; pi == nil || pi.Label == Private {
			it.Label = Private
		}
	}
	if err := ix.append(record{Op: "put", Item: &it}); err != nil {
		return "", err
	}
	ix.apply(record{Op: "put", Item: &it})
	return it.ID, ix.maybeCompact()
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
	it, ok := ix.items[id]
	if !ok {
		return Item{}, false
	}
	return *it, true
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
	var stale []Item
	for _, it := range ix.items {
		if it.VecID != want {
			stale = append(stale, *it)
			if len(stale) >= limit {
				break
			}
		}
	}
	ix.mu.RUnlock()
	n := 0
	for _, it := range stale {
		vs, err := ix.emb.Embed([]string{searchText(&it)})
		if err != nil || len(vs) != 1 {
			return n, err
		}
		ix.mu.Lock()
		cur := ix.items[it.ID]
		if cur != nil && cur.VecID != want {
			up := *cur
			up.Vector, up.VecID = vs[0], want
			if err := ix.append(record{Op: "put", Item: &up}); err != nil {
				ix.mu.Unlock()
				return n, err
			}
			ix.apply(record{Op: "put", Item: &up})
			n++
		}
		err = ix.maybeCompact()
		ix.mu.Unlock()
		if err != nil {
			return n, err
		}
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
// with their facts and vectors, records a tombstone for each requested and
// removed ID, rewrites the store so no copy remains in it, and then calls
// the OnDelete hooks for each of those IDs, including requested IDs that
// were not indexed (the event bus may still hold them). Hook errors are
// returned after the deletion is durable.
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
		for id, it := range ix.items {
			if gone[id] {
				continue
			}
			for _, p := range it.Source.DerivedFrom {
				if p == cur {
					gone[id] = true
					queue = append(queue, id)
					break
				}
			}
		}
	}
	var rep DeleteReport
	removed := map[string]*Item{}
	oldTombs := map[string]time.Time{}
	now := ix.now()
	all := make([]string, 0, len(gone))
	for id := range gone {
		all = append(all, id)
		if t, ok := ix.tombs[id]; ok {
			oldTombs[id] = t
		}
		ix.tombs[id] = now
		if it := ix.items[id]; it != nil {
			removed[id] = it
			delete(ix.items, id)
			ix.all.remove(id)
			ix.pub.remove(id)
		}
	}
	sort.Strings(all)
	if err := ix.compact(); err != nil {
		// Not durable: restore so memory matches the store.
		for _, it := range removed {
			ix.apply(record{Op: "put", Item: it})
		}
		for id := range gone {
			delete(ix.tombs, id)
		}
		for id, t := range oldTombs {
			ix.tombs[id] = t
		}
		ix.mu.Unlock()
		return DeleteReport{}, err
	}
	srcs := map[string]Source{}
	for _, id := range all {
		if it := removed[id]; it != nil {
			rep.Items = append(rep.Items, id)
			rep.Sources = append(rep.Sources, it.Source)
			srcs[id] = it.Source
		}
	}
	hooks := append([]func(Deleted) error{}, ix.onDelete...)
	ix.mu.Unlock()
	var errs []error
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
		if !publicKinds[cur.Source.Kind] {
			return ErrNotRelabelable
		}
		for _, p := range cur.Source.DerivedFrom {
			if pi := ix.items[p]; pi == nil || pi.Label != Public {
				return ErrNotRelabelable
			}
		}
		if err := ix.append(record{Op: "used", ID: msg.ID}); err != nil {
			return err
		}
		ix.used[msg.ID] = true
	}
	by := msg.ID
	up := *cur
	up.Label, up.LabelBy = l, by
	if err := ix.append(record{Op: "put", Item: &up}); err != nil {
		return err
	}
	ix.apply(record{Op: "put", Item: &up})
	if l == Private {
		// Raise everything derived from it too, transitively.
		for changed := true; changed; {
			changed = false
			for _, it := range ix.items {
				if it.Label != Public {
					continue
				}
				for _, p := range it.Source.DerivedFrom {
					if pi := ix.items[p]; pi == nil || pi.Label != Public {
						d := *it
						d.Label, d.LabelBy = Private, ""
						if err := ix.append(record{Op: "put", Item: &d}); err != nil {
							return err
						}
						ix.apply(record{Op: "put", Item: &d})
						changed = true
						break
					}
				}
			}
		}
	}
	return ix.maybeCompact()
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
	if err := ix.compact(); err != nil {
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
	if err := ix.compact(); err != nil {
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
// (default policy: 30 days).
func (ix *Index) PruneTombstones(maxAge time.Duration) (int, error) {
	if maxAge < MinTombstoneAge {
		return 0, fmt.Errorf("recall: tombstones must be kept at least %v", MinTombstoneAge)
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	cut := ix.now().Add(-maxAge)
	old := map[string]time.Time{}
	for id, t := range ix.tombs {
		if t.Before(cut) {
			old[id] = t
			delete(ix.tombs, id)
		}
	}
	if len(old) == 0 {
		return 0, nil
	}
	if err := ix.compact(); err != nil {
		for id, t := range old {
			ix.tombs[id] = t
		}
		return 0, err
	}
	return len(old), nil
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
	eligible := func(it *Item) bool {
		if q.PublicOnly && it.Label != Public {
			return false
		}
		if len(kinds) > 0 && !kinds[it.Source.Kind] {
			return false
		}
		if q.Fact != nil {
			for _, f := range it.Facts {
				if q.Fact.match(f) {
					return true
				}
			}
			return false
		}
		return true
	}

	scores := map[string]float64{}
	if strings.TrimSpace(q.Text) == "" {
		if q.Fact == nil {
			return nil
		}
		for id, it := range ix.items {
			if eligible(it) {
				scores[id] = 1
			}
		}
	} else {
		text := ix.all
		if q.PublicOnly {
			text = ix.pub
		}
		bm := text.score(q.Text)
		var max float64
		for id, s := range bm {
			if s > max && eligible(ix.items[id]) {
				max = s
			}
		}
		var qv []float32
		embID := ix.embID()
		if ix.emb != nil {
			if vs, err := ix.emb.Embed([]string{q.Text}); err == nil && len(vs) == 1 {
				qv = vs[0]
			}
		}
		floor := ix.minCosine()
		for id, it := range ix.items {
			if !eligible(it) {
				continue
			}
			var s float64
			if b := bm[id]; b > 0 && max > 0 {
				s += 0.6 * b / max
			}
			if it.VecID == embID {
				if c := cosine(qv, it.Vector); c >= floor {
					s += 0.4 * c
				}
			}
			if s > 0 {
				scores[id] = s
			}
		}
	}

	out := make([]Result, 0, len(scores))
	for id, s := range scores {
		it := ix.items[id]
		out = append(out, Result{ID: id, Source: it.Source, Label: it.Label, Text: it.Text,
			Facts: append([]Fact(nil), it.Facts...), Score: s})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if !out[i].Source.Seen.Equal(out[j].Source.Seen) {
			return out[i].Source.Seen.After(out[j].Source.Seen)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (ix *Index) append(r record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := ix.store.Append(append(b, '\n')); err != nil {
		return err
	}
	ix.lines++
	return nil
}

func (ix *Index) apply(r record) {
	switch r.Op {
	case "hdr":
		if r.Header == nil {
			return
		}
		ix.hdrEmb = r.Header.Embedder
		if !ix.keyGiven && r.Header.Key != "" {
			if k, err := hex.DecodeString(r.Header.Key); err == nil && len(k) >= 16 {
				ix.keyer = Keyer{key: k}
			}
		}
	case "put":
		if r.Item == nil {
			return
		}
		it := *r.Item
		ix.items[it.ID] = &it
		st := searchText(&it)
		ix.all.add(it.ID, st)
		if it.Label == Public {
			ix.pub.add(it.ID, st)
		} else {
			ix.pub.remove(it.ID)
		}
	case "pref":
		if r.Pref != nil {
			ix.prefs[r.Pref.Key] = *r.Pref
		}
	case "tomb":
		if r.ID != "" {
			ix.tombs[r.ID] = r.At
		}
	case "used":
		if r.ID != "" {
			ix.used[r.ID] = true
		}
	}
}

// maybeCompact rewrites the store once replaced items make up more than
// half of it, so an overwritten version does not linger indefinitely.
func (ix *Index) maybeCompact() error {
	live := len(ix.items) + len(ix.prefs) + len(ix.tombs) + len(ix.used) + 1
	if ix.lines > 64 && ix.lines > 2*live {
		return ix.compact()
	}
	return nil
}

// compact rewrites the store with only the live state: header, items,
// preferences and tombstones. Caller holds mu.
func (ix *Index) compact() error {
	var buf []byte
	n := 0
	put := func(r record) error {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		buf = append(append(buf, b...), '\n')
		n++
		return nil
	}
	h := &header{Embedder: ix.embID()}
	if !ix.keyGiven {
		h.Key = hex.EncodeToString(ix.keyer.key)
	}
	if err := put(record{Op: "hdr", Header: h}); err != nil {
		return err
	}
	ids := make([]string, 0, len(ix.items))
	for id := range ix.items {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := put(record{Op: "put", Item: ix.items[id]}); err != nil {
			return err
		}
	}
	keys := make([]string, 0, len(ix.prefs))
	for k := range ix.prefs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := ix.prefs[k]
		if err := put(record{Op: "pref", Pref: &p}); err != nil {
			return err
		}
	}
	tids := make([]string, 0, len(ix.tombs))
	for id := range ix.tombs {
		tids = append(tids, id)
	}
	sort.Strings(tids)
	for _, id := range tids {
		if err := put(record{Op: "tomb", ID: id, At: ix.tombs[id]}); err != nil {
			return err
		}
	}
	uids := make([]string, 0, len(ix.used))
	for id := range ix.used {
		uids = append(uids, id)
	}
	sort.Strings(uids)
	for _, id := range uids {
		if err := put(record{Op: "used", ID: id}); err != nil {
			return err
		}
	}
	if err := ix.store.Rewrite(buf); err != nil {
		return err
	}
	ix.lines = n
	ix.hdrEmb = h.Embedder
	return nil
}
