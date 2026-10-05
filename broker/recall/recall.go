package recall

import (
	"crypto/sha256"
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

func (l Label) norm() Label {
	if l == Public {
		return Public
	}
	return Private
}

// ownerData are source kinds that are owner data whatever the caller
// declares (REV-5: mail, files, owner chat; D1: task text unless the owner
// marked the task PUBLIC, which the caller states with Label Public).
var ownerData = map[string]bool{
	"mail": true, "file": true, "calendar": true, "contact": true,
	"owner": true, "credentialed": true, "preference": true,
}

// Source is an item's provenance (CAP-3).
type Source struct {
	// Kind is where the item came from: mail, file, calendar, web, timer,
	// task, agent, owner, credentialed (an executor read), and so on.
	Kind    string    `json:"kind"`
	Account string    `json:"account,omitempty"`
	Ref     string    `json:"ref"` // message ID, path, URL, task ID
	Seen    time.Time `json:"seen"`
	// DerivedFrom lists the items this one was computed from (a summary,
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
}

// OwnerMessage is an authenticated owner-channel message (owner text or
// local UI action), the only provenance a preference may have.
type OwnerMessage struct {
	ID      string    `json:"id"`
	Channel string    `json:"channel"` // "sms", "voice", "local-ui"
	At      time.Time `json:"at"`
}

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

var (
	ErrNoSource     = errors.New("recall: item needs a source kind and ref")
	ErrNotOwner     = errors.New("recall: preferences are written only from an authenticated owner-channel message")
	ErrNoLabeler    = errors.New("recall: private results need a labeler to raise the caller (REV-5)")
	ErrUnknownPref  = errors.New("recall: no such preference")
	ErrCorruptStore = errors.New("recall: store has an unreadable record")
)

// Index is the broker-owned recall index (CAP-3): full text, embeddings and
// structured facts over everything the system has seen, with provenance.
// Agents reach it only through Search and PreferencesFor, which raise the
// caller's label before returning owner data, and see results only as
// untrusted content (Render). Only the broker writes to it.
type Index struct {
	mu       sync.RWMutex
	store    Store
	scrub    *Scrubber
	emb      Embedder
	labels   Labeler
	owner    OwnerAuth
	now      func() time.Time
	items    map[string]*Item
	text     *textIndex
	prefs    map[string]Preference
	onDelete []func(Source)
	lines    int // records in the store
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

// WithClock sets the clock.
func WithClock(now func() time.Time) Option { return func(ix *Index) { ix.now = now } }

type record struct {
	Op   string      `json:"op"` // "put", "pref"
	Item *Item       `json:"item,omitempty"`
	Pref *Preference `json:"pref,omitempty"`
}

// Open loads the index from store.
func Open(store Store, opts ...Option) (*Index, error) {
	ix := &Index{
		store: store,
		scrub: NewScrubber(nil),
		emb:   HashEmbedder{},
		now:   func() time.Time { return time.Now().UTC() },
		items: map[string]*Item{},
		text:  newTextIndex(),
		prefs: map[string]Preference{},
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
			return nil, fmt.Errorf("%w: %v", ErrCorruptStore, err)
		}
		ix.apply(r)
	}
	ix.lines = len(lines)
	if torn {
		if err := ix.compact(); err != nil {
			return nil, err
		}
	}
	return ix, nil
}

// ItemID is the stable ID of the item for a source. Re-ingesting the same
// source replaces the item. The hash is of the raw ref, so a ref the
// scrubber shortens still maps to one item and can be deleted by its raw
// form.
func ItemID(kind, account, ref string) string {
	h := sha256.Sum256([]byte(kind + "\x00" + account + "\x00" + ref))
	return hex.EncodeToString(h[:12])
}

// Ingest indexes an item, replacing any earlier item from the same source.
// Text, facts and ref are scrubbed of credentials first (CRED-1). Ingest
// never creates a preference, whatever the text says (CAP-3).
func (ix *Index) Ingest(it Item) (string, error) {
	if it.Source.Kind == "" || it.Source.Ref == "" {
		return "", ErrNoSource
	}
	it.ID = ItemID(it.Source.Kind, it.Source.Account, it.Source.Ref)
	it.Label = it.Label.norm()
	if ownerData[it.Source.Kind] {
		it.Label = Private
	}
	if it.Source.Seen.IsZero() {
		it.Source.Seen = ix.now()
	}
	it.Source.Ref = ix.scrub.Scrub(it.Source.Ref)
	it.Text = ix.scrub.Scrub(it.Text)
	facts := make([]Fact, 0, len(it.Facts))
	for _, f := range it.Facts {
		facts = append(facts, Fact{ix.scrub.Scrub(f.Subject), ix.scrub.Scrub(f.Predicate), ix.scrub.Scrub(f.Object)})
	}
	it.Facts = facts
	it.Source.DerivedFrom = append([]string(nil), it.Source.DerivedFrom...)
	it.Vector = nil
	if ix.emb != nil {
		if vs, err := ix.emb.Embed([]string{searchText(&it)}); err == nil && len(vs) == 1 {
			it.Vector = vs[0]
		}
	}

	ix.mu.Lock()
	defer ix.mu.Unlock()
	// A derived item is at least as private as its parents.
	for _, p := range it.Source.DerivedFrom {
		if pi := ix.items[p]; pi != nil && pi.Label == Private {
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

// DeleteReport lists what a deletion removed.
type DeleteReport struct {
	Items   []string
	Sources []Source
}

// OnDelete registers a hook called with each deleted item's source after a
// deletion is durable, so other stores (the event bus, caches) drop their
// copies (CAP-3: deletion requests propagate).
func (ix *Index) OnDelete(f func(Source)) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.onDelete = append(ix.onDelete, f)
}

// DeleteSource deletes the item for a source, by its raw ref.
func (ix *Index) DeleteSource(kind, account, ref string) (DeleteReport, error) {
	return ix.Delete(ItemID(kind, account, ref))
}

// Delete removes items, every item derived from them (transitively), their
// facts and vectors, and rewrites the store so no copy remains in it. Then
// it calls the OnDelete hooks.
func (ix *Index) Delete(ids ...string) (DeleteReport, error) {
	ix.mu.Lock()
	gone := map[string]bool{}
	queue := []string{}
	for _, id := range ids {
		if _, ok := ix.items[id]; ok && !gone[id] {
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
	for id := range gone {
		removed[id] = ix.items[id]
		rep.Items = append(rep.Items, id)
		rep.Sources = append(rep.Sources, ix.items[id].Source)
		delete(ix.items, id)
		ix.text.remove(id)
	}
	sort.Strings(rep.Items)
	if len(gone) > 0 {
		if err := ix.compact(); err != nil {
			// Not durable: restore so memory matches the store.
			for id, it := range removed {
				ix.items[id] = it
				ix.text.add(id, searchText(it))
			}
			ix.mu.Unlock()
			return DeleteReport{}, err
		}
	}
	hooks := append([]func(Source){}, ix.onDelete...)
	ix.mu.Unlock()
	for _, s := range rep.Sources {
		for _, h := range hooks {
			h(s)
		}
	}
	return rep, nil
}

// SetPreference stores or replaces an owner preference. messageID must name
// a message the owner channel authenticated; it becomes the provenance.
func (ix *Index) SetPreference(messageID, key, value string) error {
	msg, err := ix.ownerMessage(messageID)
	if err != nil {
		return err
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("recall: preference key is empty")
	}
	p := Preference{Key: key, Value: ix.scrub.Scrub(value), Provenance: msg}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.append(record{Op: "pref", Pref: &p}); err != nil {
		return err
	}
	ix.apply(record{Op: "pref", Pref: &p})
	// Rewrite so an edited value leaves no earlier copy in the store.
	return ix.compact()
}

// DeletePreference removes an owner preference, on an authenticated owner
// message.
func (ix *Index) DeletePreference(messageID, key string) error {
	if _, err := ix.ownerMessage(messageID); err != nil {
		return err
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	old, ok := ix.prefs[key]
	if !ok {
		return ErrUnknownPref
	}
	delete(ix.prefs, key)
	if err := ix.compact(); err != nil {
		ix.prefs[key] = old
		return err
	}
	return nil
}

func (ix *Index) ownerMessage(id string) (OwnerMessage, error) {
	if ix.owner == nil || id == "" {
		return OwnerMessage{}, ErrNotOwner
	}
	msg, ok := ix.owner(id)
	if !ok || msg.ID != id {
		return OwnerMessage{}, ErrNotOwner
	}
	return msg, nil
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
// They are owner data, so the machine is raised to private first (REV-5).
func (ix *Index) PreferencesFor(machine string) ([]Preference, error) {
	ps := ix.Preferences()
	if len(ps) == 0 {
		return nil, nil
	}
	if err := ix.raise(machine); err != nil {
		return nil, err
	}
	return ps, nil
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
	// PublicOnly restricts results to public items, so a public machine can
	// search without rising to private.
	PublicOnly bool
}

// Result is one search hit.
type Result struct {
	ID     string
	Source Source
	Label  Label
	Text   string
	Facts  []Fact
	Score  float64
}

// minCosine is the similarity below which an embedding match alone is noise.
// Tuned for HashEmbedder; a model embedder may need its own value.
const minCosine = 0.2

// Lookup searches on the broker's or owner's behalf. It changes no label.
func (ix *Index) Lookup(q Query) []Result {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.search(q)
}

// Search searches on behalf of an agent machine. If any result is private,
// the machine is raised to private before the results are returned; if it
// cannot be raised, no results are returned (REV-5). Deliver results to the
// agent only through Render (CAP-3: untrusted content, never instructions).
func (ix *Index) Search(machine string, q Query) ([]Result, error) {
	rs := ix.Lookup(q)
	for _, r := range rs {
		if r.Label != Public {
			if err := ix.raise(machine); err != nil {
				return nil, err
			}
			break
		}
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
		bm := ix.text.score(q.Text)
		var max float64
		for _, s := range bm {
			if s > max {
				max = s
			}
		}
		var qv []float32
		if ix.emb != nil {
			if vs, err := ix.emb.Embed([]string{q.Text}); err == nil && len(vs) == 1 {
				qv = vs[0]
			}
		}
		for id, it := range ix.items {
			if !eligible(it) {
				continue
			}
			var s float64
			if b := bm[id]; b > 0 {
				s += 0.6 * b / max
			}
			if c := cosine(qv, it.Vector); c >= minCosine {
				s += 0.4 * c
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
	case "put":
		if r.Item == nil {
			return
		}
		it := *r.Item
		ix.items[it.ID] = &it
		ix.text.add(it.ID, searchText(&it))
	case "pref":
		if r.Pref != nil {
			ix.prefs[r.Pref.Key] = *r.Pref
		}
	}
}

// maybeCompact rewrites the store once replaced items make up more than
// half of it, so an overwritten version does not linger indefinitely.
func (ix *Index) maybeCompact() error {
	live := len(ix.items) + len(ix.prefs)
	if ix.lines > 64 && ix.lines > 2*live {
		return ix.compact()
	}
	return nil
}

// compact rewrites the store with only the live state. Caller holds mu.
func (ix *Index) compact() error {
	var buf []byte
	ids := make([]string, 0, len(ix.items))
	for id := range ix.items {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	n := 0
	for _, id := range ids {
		b, err := json.Marshal(record{Op: "put", Item: ix.items[id]})
		if err != nil {
			return err
		}
		buf = append(append(buf, b...), '\n')
		n++
	}
	keys := make([]string, 0, len(ix.prefs))
	for k := range ix.prefs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := ix.prefs[k]
		b, err := json.Marshal(record{Op: "pref", Pref: &p})
		if err != nil {
			return err
		}
		buf = append(append(buf, b...), '\n')
		n++
	}
	if err := ix.store.Rewrite(buf); err != nil {
		return err
	}
	ix.lines = n
	return nil
}
