package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/recall"
)

// Kind is an event source (CAP-4).
type Kind string

const (
	Mail     Kind = "mail"
	File     Kind = "file"
	Calendar Kind = "calendar"
	Web      Kind = "web"
	Timer    Kind = "timer"
)

// ownerData kinds are private whatever the publisher declares (REV-5).
var ownerData = map[Kind]bool{Mail: true, File: true, Calendar: true}

// Event is one thing that happened. Ref names the thing (message ID, path,
// URL, timer name) and Version the state seen (message ID again, mtime,
// content hash, due time). The bus delivers each (kind, account, ref,
// version) once, so a watcher that republishes an unchanged page or an
// already-seen mail causes no work.
type Event struct {
	ID      string       `json:"id"`
	Kind    Kind         `json:"kind"`
	Account string       `json:"account,omitempty"`
	Ref     string       `json:"ref"`
	Version string       `json:"version,omitempty"`
	At      time.Time    `json:"at"`
	Label   recall.Label `json:"label"`
	Summary string       `json:"summary,omitempty"`
	Body    string       `json:"body,omitempty"`
}

// EventID is the dedupe key of an event.
func EventID(k Kind, account, ref, version string) string {
	h := sha256.Sum256([]byte(string(k) + "\x00" + account + "\x00" + ref + "\x00" + version))
	return hex.EncodeToString(h[:12])
}

// Delivery is one event handed to one trigger. Key is stable across
// retries and restarts, so the work a trigger starts can be made idempotent
// on it (an intent ID, a task ID).
type Delivery struct {
	Key     string
	Trigger string
	Attempt int
	Event   Event
}

// Trigger starts work when a matching event arrives (CAP-4). Triggers are
// broker-side: the work they start is bound to a task and an agent machine,
// and that machine receives the event's label with its content (REV-5).
type Trigger struct {
	Name  string
	Kinds []Kind           // empty means all kinds
	Match func(Event) bool // nil means every event of those kinds
	Start func(ctx context.Context, d Delivery) error
}

func (t Trigger) matches(e Event) bool {
	if len(t.Kinds) > 0 {
		ok := false
		for _, k := range t.Kinds {
			if k == e.Kind {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return t.Match == nil || t.Match(e)
}

// Schedule is a timer source: it fires every Every from First. Missed
// firings during downtime coalesce into one event for the latest due time.
type Schedule struct {
	Name    string
	First   time.Time
	Every   time.Duration // 0 fires once, at First
	Label   recall.Label  // task text is private unless marked PUBLIC (D1)
	Summary string
}

var (
	ErrNoRef        = errors.New("events: event needs a kind and ref")
	ErrTrigger      = errors.New("events: trigger needs a unique name and a Start function")
	ErrCorruptStore = errors.New("events: store has an unreadable record")
)

type record struct {
	Op      string   `json:"op"` // pub, ack, fail, dead, seen, timer
	Event   *Event   `json:"event,omitempty"`
	Targets []string `json:"targets,omitempty"`
	ID      string   `json:"id,omitempty"`
	Trigger string   `json:"trigger,omitempty"`
	Name    string   `json:"name,omitempty"`
	Due     string   `json:"due,omitempty"`
}

type entry struct {
	ev      Event
	pending map[string]int // trigger -> failed attempts so far
}

// Bus is the durable event bus (CAP-4). Published events are journaled
// before Publish returns; deliveries are at-least-once per (event,
// trigger) and survive restarts. Settled events keep only their ID: their
// content leaves memory at once and the store at the next compaction, which
// runs once settled records outnumber live ones (and on every Forget).
type Bus struct {
	mu        sync.Mutex
	store     recall.Store
	scrub     *recall.Scrubber
	triggers  map[string]Trigger
	att       *Attention
	now       func() time.Time
	maxTries  int
	seen      map[string]bool
	live      map[string]*entry
	order     []string
	timers    map[string]Schedule
	lastFired map[string]time.Time
	lines     int
	wake      chan struct{}
}

// Option configures a Bus.
type Option func(*Bus)

// WithClock sets the clock.
func WithClock(now func() time.Time) Option { return func(b *Bus) { b.now = now } }

// WithAttention routes failed deliveries to the owner's digest.
func WithAttention(a *Attention) Option { return func(b *Bus) { b.att = a } }

// WithMaxAttempts sets how many times a delivery is tried (default 5).
func WithMaxAttempts(n int) Option { return func(b *Bus) { b.maxTries = n } }

// WithVaultRedactor adds the vault's redactor ahead of the scrubber.
func WithVaultRedactor(r func(string) string) Option {
	return func(b *Bus) { b.scrub = recall.NewScrubber(r) }
}

// Open loads the bus from store. Triggers must be the same set on every
// start: deliveries recorded for a trigger that is no longer registered are
// dropped with a digest note.
func Open(store recall.Store, triggers []Trigger, opts ...Option) (*Bus, error) {
	b := &Bus{
		store:     store,
		scrub:     recall.NewScrubber(nil),
		triggers:  map[string]Trigger{},
		now:       func() time.Time { return time.Now().UTC() },
		maxTries:  5,
		seen:      map[string]bool{},
		live:      map[string]*entry{},
		timers:    map[string]Schedule{},
		lastFired: map[string]time.Time{},
		wake:      make(chan struct{}, 1),
	}
	for _, o := range opts {
		o(b)
	}
	for _, t := range triggers {
		if t.Name == "" || t.Start == nil || b.triggers[t.Name].Name != "" {
			return nil, fmt.Errorf("%w: %q", ErrTrigger, t.Name)
		}
		b.triggers[t.Name] = t
	}
	data, err := store.ReadAll()
	if err != nil {
		return nil, err
	}
	lines, torn := recall.Lines(data)
	for _, l := range lines {
		var r record
		if err := json.Unmarshal(l, &r); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCorruptStore, err)
		}
		b.apply(r)
	}
	b.lines = len(lines)
	var dropped []string
	for _, id := range b.order {
		e := b.live[id]
		for t := range e.pending {
			if _, ok := b.triggers[t]; !ok {
				delete(e.pending, t)
				dropped = append(dropped, t)
			}
		}
	}
	b.settle()
	if torn || len(dropped) > 0 {
		if err := b.compact(); err != nil {
			return nil, err
		}
	}
	if b.att != nil && len(dropped) > 0 {
		sort.Strings(dropped)
		b.att.Note(fmt.Sprintf("Event deliveries dropped for %d removed trigger(s): %v", len(dropped), dedupe(dropped)))
	}
	return b, nil
}

func dedupe(ss []string) []string {
	var out []string
	for i, s := range ss {
		if i == 0 || ss[i-1] != s {
			out = append(out, s)
		}
	}
	return out
}

// Publish records an event and queues it for every matching trigger. It
// returns false if the event was already seen. Summary, body and ref are
// scrubbed of credentials before they are stored (CRED-1); the ID is
// computed from the raw values first.
func (b *Bus) Publish(e Event) (string, bool, error) {
	if e.Kind == "" || e.Ref == "" {
		return "", false, ErrNoRef
	}
	e.ID = EventID(e.Kind, e.Account, e.Ref, e.Version)
	if e.Label != recall.Public || ownerData[e.Kind] {
		e.Label = recall.Private
	}
	if e.At.IsZero() {
		e.At = b.now()
	}
	e.Ref = b.scrub.Scrub(e.Ref)
	e.Version = b.scrub.Scrub(e.Version)
	e.Summary = b.scrub.Scrub(e.Summary)
	e.Body = b.scrub.Scrub(e.Body)

	b.mu.Lock()
	defer b.mu.Unlock()
	return b.publishLocked(e)
}

func (b *Bus) publishLocked(e Event) (string, bool, error) {
	if b.seen[e.ID] {
		return e.ID, false, nil
	}
	var targets []string
	for name, t := range b.triggers {
		if t.matches(e) {
			targets = append(targets, name)
		}
	}
	sort.Strings(targets)
	r := record{Op: "pub", Event: &e, Targets: targets}
	if len(targets) == 0 {
		r = record{Op: "seen", ID: e.ID}
	}
	if err := b.append(r); err != nil {
		return "", false, err
	}
	b.apply(r)
	b.signal()
	return e.ID, true, nil
}

func (b *Bus) signal() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// AddTimer registers a timer source. Its last firing is read from the
// store, so a restart neither repeats nor loses a due time.
func (b *Bus) AddTimer(s Schedule) error {
	if s.Name == "" || s.First.IsZero() || s.Every < 0 {
		return errors.New("events: timer needs a name and a first time")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.timers[s.Name] = s
	return nil
}

// Tick fires every timer that has come due by now.
func (b *Bus) Tick(now time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	names := make([]string, 0, len(b.timers))
	for n := range b.timers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := b.timers[n]
		if now.Before(s.First) {
			continue
		}
		due := s.First
		if s.Every > 0 {
			due = s.First.Add(now.Sub(s.First) / s.Every * s.Every)
		}
		if last, ok := b.lastFired[n]; ok && !due.After(last) {
			continue
		}
		dueText := due.UTC().Format(time.RFC3339Nano)
		if err := b.append(record{Op: "timer", Name: n, Due: dueText}); err != nil {
			return err
		}
		b.lastFired[n] = due
		label := s.Label
		if label != recall.Public {
			label = recall.Private
		}
		e := Event{Kind: Timer, Ref: n, Version: dueText, At: due, Label: label, Summary: b.scrub.Scrub(s.Summary)}
		e.ID = EventID(Timer, "", n, dueText)
		if _, _, err := b.publishLocked(e); err != nil {
			return err
		}
	}
	return nil
}

// Pump delivers every pending (event, trigger) pair once, in publish
// order, and returns how many deliveries succeeded. Start runs outside the
// bus lock.
func (b *Bus) Pump(ctx context.Context) int {
	type job struct {
		d Delivery
		t Trigger
	}
	b.mu.Lock()
	var jobs []job
	for _, id := range b.order {
		e := b.live[id]
		names := make([]string, 0, len(e.pending))
		for n := range e.pending {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			jobs = append(jobs, job{Delivery{Key: id + "/" + n, Trigger: n, Attempt: e.pending[n] + 1, Event: e.ev}, b.triggers[n]})
		}
	}
	b.mu.Unlock()

	ok := 0
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		err := safeStart(ctx, j.t, j.d)
		b.mu.Lock()
		e := b.live[j.d.Event.ID]
		if e == nil {
			b.mu.Unlock()
			continue // forgotten meanwhile
		}
		if _, still := e.pending[j.d.Trigger]; !still {
			b.mu.Unlock()
			continue
		}
		var r record
		switch {
		case err == nil:
			r = record{Op: "ack", ID: j.d.Event.ID, Trigger: j.d.Trigger}
			ok++
		case j.d.Attempt >= b.maxTries:
			r = record{Op: "dead", ID: j.d.Event.ID, Trigger: j.d.Trigger}
		default:
			r = record{Op: "fail", ID: j.d.Event.ID, Trigger: j.d.Trigger}
		}
		if aerr := b.append(r); aerr == nil {
			b.apply(r)
			if r.Op == "dead" && b.att != nil {
				b.att.Note(fmt.Sprintf("Could not start %s for a %s event after %d tries.", j.d.Trigger, j.d.Event.Kind, j.d.Attempt))
			}
		}
		b.settle()
		_ = b.maybeCompact()
		b.mu.Unlock()
	}
	return ok
}

func safeStart(ctx context.Context, t Trigger, d Delivery) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("events: trigger %s panicked: %v", t.Name, p)
		}
	}()
	return t.Start(ctx, d)
}

// Run ticks timers and pumps deliveries until ctx ends: at once when an
// event is published, and every interval for timers and retries.
func (b *Bus) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		_ = b.Tick(b.now())
		b.Pump(ctx)
		select {
		case <-ctx.Done():
			return
		case <-b.wake:
		case <-tk.C:
		}
	}
}

// Pending returns the number of undelivered (event, trigger) pairs.
func (b *Bus) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, e := range b.live {
		n += len(e.pending)
	}
	return n
}

// Forget drops every event, pending or not, about a source and rewrites
// the store, so a deletion request reaches the bus's copy too (CAP-3). Only
// the event IDs are kept, so the same item is not delivered again. ref is
// compared after scrubbing, as stored.
func (b *Bus) Forget(kind Kind, account, ref string) error {
	ref = b.scrub.Scrub(ref)
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, e := range b.live {
		if e.ev.Kind == kind && e.ev.Account == account && e.ev.Ref == ref {
			delete(b.live, id)
		}
	}
	b.reorder()
	// Always rewrite: a settled event's content can still be in the store
	// until the next compaction.
	return b.compact()
}

// ForgetSource adapts Forget to recall.Index.OnDelete.
func (b *Bus) ForgetSource(s recall.Source) {
	_ = b.Forget(Kind(s.Kind), s.Account, s.Ref)
}

func (b *Bus) append(r record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := b.store.Append(append(data, '\n')); err != nil {
		return err
	}
	b.lines++
	return nil
}

func (b *Bus) apply(r record) {
	switch r.Op {
	case "pub":
		if r.Event == nil {
			return
		}
		b.seen[r.Event.ID] = true
		e := &entry{ev: *r.Event, pending: map[string]int{}}
		for _, t := range r.Targets {
			e.pending[t] = 0
		}
		b.live[r.Event.ID] = e
		b.order = append(b.order, r.Event.ID)
	case "seen":
		b.seen[r.ID] = true
	case "ack", "dead":
		if e := b.live[r.ID]; e != nil {
			delete(e.pending, r.Trigger)
		}
	case "fail":
		if e := b.live[r.ID]; e != nil {
			if _, ok := e.pending[r.Trigger]; ok {
				e.pending[r.Trigger]++
			}
		}
	case "timer":
		if t, err := time.Parse(time.RFC3339Nano, r.Due); err == nil {
			b.lastFired[r.Name] = t
		}
	}
}

// settle drops content of events with no pending delivery.
func (b *Bus) settle() {
	changed := false
	for id, e := range b.live {
		if len(e.pending) == 0 {
			delete(b.live, id)
			changed = true
		}
	}
	if changed {
		b.reorder()
	}
}

func (b *Bus) reorder() {
	out := b.order[:0]
	for _, id := range b.order {
		if b.live[id] != nil {
			out = append(out, id)
		}
	}
	b.order = out
}

// maybeCompact rewrites the store when settled records dominate it, so
// delivered event content does not linger.
func (b *Bus) maybeCompact() error {
	if b.lines > 64 && b.lines > 2*(len(b.live)+len(b.lastFired))+len(b.seen) {
		return b.compact()
	}
	return nil
}

func (b *Bus) compact() error {
	var buf []byte
	put := func(r record) error {
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		buf = append(append(buf, data...), '\n')
		return nil
	}
	ids := make([]string, 0, len(b.seen))
	for id := range b.seen {
		if b.live[id] == nil {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	n := 0
	for _, id := range ids {
		if err := put(record{Op: "seen", ID: id}); err != nil {
			return err
		}
		n++
	}
	names := make([]string, 0, len(b.lastFired))
	for name := range b.lastFired {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := put(record{Op: "timer", Name: name, Due: b.lastFired[name].UTC().Format(time.RFC3339Nano)}); err != nil {
			return err
		}
		n++
	}
	for _, id := range b.order {
		e := b.live[id]
		ev := e.ev
		targets := make([]string, 0, len(e.pending))
		for t := range e.pending {
			targets = append(targets, t)
		}
		sort.Strings(targets)
		if err := put(record{Op: "pub", Event: &ev, Targets: targets}); err != nil {
			return err
		}
		n++
		for _, t := range targets {
			for k := 0; k < e.pending[t]; k++ {
				if err := put(record{Op: "fail", ID: id, Trigger: t}); err != nil {
					return err
				}
				n++
			}
		}
	}
	if err := b.store.Rewrite(buf); err != nil {
		return err
	}
	b.lines = n
	return nil
}

// IndexInto returns a trigger that records every event in the recall index
// with its provenance (CAP-3: everything the system has seen).
func IndexInto(ix *recall.Index) Trigger {
	return Trigger{
		Name: "recall",
		Start: func(_ context.Context, d Delivery) error {
			e := d.Event
			text := e.Summary
			if e.Body != "" {
				if text != "" {
					text += "\n"
				}
				text += e.Body
			}
			_, err := ix.Ingest(recall.Item{
				Source: recall.Source{Kind: string(e.Kind), Account: e.Account, Ref: e.Ref, Seen: e.At},
				Label:  e.Label,
				Text:   text,
			})
			return err
		},
	}
}
