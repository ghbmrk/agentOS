package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

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

// MaxBody bounds an event body after scrubbing; longer bodies are cut.
const MaxBody = 64 << 10

// Event is one thing that happened. Ref names the thing (message ID, path,
// URL, timer name) and Version the state seen (message ID again, mtime,
// content hash, due time). The bus delivers each (kind, account, ref,
// version) once, so a watcher may republish an unchanged page or an
// already-seen mail without causing work.
type Event struct {
	// ID and Source are keyed identities computed from the raw ref and
	// version before scrubbing (recall.Keyer). Source equals the recall
	// item ID for the same source, so deletions match.
	ID      string       `json:"id"`
	Source  string       `json:"src"`
	Kind    Kind         `json:"kind"`
	Account string       `json:"account,omitempty"`
	Ref     string       `json:"ref"` // scrubbed, for display
	Version string       `json:"version,omitempty"`
	At      time.Time    `json:"at"`
	Label   recall.Label `json:"label"`
	Summary string       `json:"summary,omitempty"`
	Body    string       `json:"body,omitempty"`
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
	ErrReservedKind = errors.New("events: only the owner channel produces this kind")
	ErrTrigger      = errors.New("events: trigger needs a unique name and a Start function")
	ErrConfig       = errors.New("events: Config needs Log, Seen and a Keyer")
)

// Config is what a Bus is opened with.
type Config struct {
	// Log holds live events, delivery progress and timer state. It is
	// rewritten as events settle, so delivered content leaves it.
	Log recall.Store
	// Seen is an append-only list of event IDs (hashes only, no content),
	// so dedupe never needs the content kept.
	Seen recall.Store
	// Keyer must be the recall index's (Index.Keyer), so event sources and
	// recall items share identities.
	Keyer    recall.Keyer
	Triggers []Trigger
}

type record struct {
	Op      string    `json:"op"` // pub, ack, fail, dead, timer
	Event   *Event    `json:"event,omitempty"`
	Targets []string  `json:"targets,omitempty"`
	ID      string    `json:"id,omitempty"`
	Trigger string    `json:"trigger,omitempty"`
	Src     string    `json:"src,omitempty"`
	At      time.Time `json:"at,omitempty"`
}

type entry struct {
	ev      Event
	pending map[string]int       // trigger -> failed attempts so far
	next    map[string]time.Time // trigger -> earliest retry (not persisted)
}

// Bus is the durable event bus (CAP-4). Published events are journaled
// before Publish returns; deliveries are at-least-once per (event, trigger)
// and survive restarts. A settled event keeps only its ID: its content
// leaves memory at once and the log within a few settlements (and at once
// on Forget).
type Bus struct {
	mu        sync.Mutex
	log, seen recall.Store
	keyer     recall.Keyer
	scrub     *recall.Scrubber
	triggers  map[string]Trigger
	att       *Attention
	now       func() time.Time
	maxTries  int
	seenIDs   map[string]bool
	live      map[string]*entry
	order     []string
	timers    map[string]Schedule
	lastFired map[string]time.Time // timer source ID -> latest due fired
	lines     int                  // records in the log
	stale     int                  // settled events whose records are still in the log
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

// staleLimit is how many settled events may keep records in the log before
// it is rewritten.
const staleLimit = 8

// Open loads the bus. Triggers must be the same set on every start:
// deliveries recorded for a trigger that is no longer registered are
// dropped with a digest note. Unreadable records are skipped.
func Open(cfg Config, opts ...Option) (*Bus, error) {
	if cfg.Log == nil || cfg.Seen == nil || !cfg.Keyer.Valid() {
		return nil, ErrConfig
	}
	b := &Bus{
		log:       cfg.Log,
		seen:      cfg.Seen,
		keyer:     cfg.Keyer,
		scrub:     recall.NewScrubber(nil),
		triggers:  map[string]Trigger{},
		now:       func() time.Time { return time.Now().UTC() },
		maxTries:  5,
		seenIDs:   map[string]bool{},
		live:      map[string]*entry{},
		timers:    map[string]Schedule{},
		lastFired: map[string]time.Time{},
		wake:      make(chan struct{}, 1),
	}
	for _, o := range opts {
		o(b)
	}
	for _, t := range cfg.Triggers {
		if t.Name == "" || t.Start == nil || b.triggers[t.Name].Name != "" {
			return nil, fmt.Errorf("%w: %q", ErrTrigger, t.Name)
		}
		b.triggers[t.Name] = t
	}
	data, err := b.seen.ReadAll()
	if err != nil {
		return nil, err
	}
	lines, _ := recall.Lines(data)
	for _, l := range lines {
		var s struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(l, &s) == nil && s.ID != "" {
			b.seenIDs[s.ID] = true
		}
	}
	data, err = b.log.ReadAll()
	if err != nil {
		return nil, err
	}
	lines, torn := recall.Lines(data)
	skipped := 0
	for _, l := range lines {
		var r record
		if err := json.Unmarshal(l, &r); err != nil {
			skipped++
			continue
		}
		b.apply(r)
	}
	b.lines = len(lines)
	// A pub whose seen line a crash cut off is recorded now, before the log
	// can be compacted without it.
	for id := range b.live {
		if !b.seenIDs[id] {
			if err := b.markSeen(id); err != nil {
				return nil, err
			}
			b.seenIDs[id] = true
		}
	}
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
	if torn || skipped > 0 || len(dropped) > 0 || b.stale > 0 {
		if err := b.compact(); err != nil {
			return nil, err
		}
	}
	if b.att != nil && len(dropped) > 0 {
		sort.Strings(dropped)
		b.att.Note(fmt.Sprintf("Some new items were not acted on because %v is no longer set up.", dedupe(dropped)))
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
// returns false if the event was already seen. Identities are computed from
// the raw ref and version; then summary, body, ref and version are scrubbed
// of credentials (CRED-1) and the body is cut to MaxBody.
func (b *Bus) Publish(e Event) (string, bool, error) {
	if e.Kind == "" || e.Ref == "" {
		return "", false, ErrNoRef
	}
	if recall.ReservedKinds[string(e.Kind)] {
		return "", false, fmt.Errorf("%w: %s", ErrReservedKind, e.Kind)
	}
	e.Source = b.keyer.SourceID(string(e.Kind), e.Account, e.Ref)
	e.ID = b.keyer.ID("evt", string(e.Kind), e.Account, e.Ref, e.Version)
	e.Label = recall.EffectiveLabel(string(e.Kind), e.Label)
	if e.At.IsZero() {
		e.At = b.now()
	}
	e.Ref = b.scrub.Scrub(e.Ref)
	e.Version = b.scrub.Scrub(e.Version)
	e.Summary = b.scrub.Scrub(e.Summary)
	e.Body = cut(b.scrub.Scrub(e.Body), MaxBody)

	b.mu.Lock()
	defer b.mu.Unlock()
	return b.publishLocked(e)
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "\n[cut]"
}

func (b *Bus) publishLocked(e Event) (string, bool, error) {
	if b.seenIDs[e.ID] {
		return e.ID, false, nil
	}
	var targets []string
	for name, t := range b.triggers {
		if t.matches(e) {
			targets = append(targets, name)
		}
	}
	sort.Strings(targets)
	if len(targets) > 0 || e.Kind == Timer {
		r := record{Op: "pub", Event: &e, Targets: targets}
		if err := b.append(r); err != nil {
			return "", false, err
		}
		b.apply(r)
		b.settle()
	}
	if err := b.markSeen(e.ID); err != nil {
		return "", false, err
	}
	b.seenIDs[e.ID] = true
	b.signal()
	return e.ID, true, nil
}

func (b *Bus) markSeen(id string) error {
	line, _ := json.Marshal(struct {
		ID string `json:"id"`
	}{id})
	return b.seen.Append(append(line, '\n'))
}

func (b *Bus) signal() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

// AddTimer registers a timer source. Its last firing is read from the
// log, so a restart neither repeats nor loses a due time.
func (b *Bus) AddTimer(s Schedule) error {
	if s.Name == "" || s.First.IsZero() || s.Every < 0 {
		return errors.New("events: timer needs a name and a first time")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.timers[s.Name] = s
	return nil
}

// Tick fires every timer that has come due by now. The firing is published
// (durably) before it counts as fired, so a crash in between repeats the
// publish, which dedupe absorbs, rather than losing it.
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
		src := b.keyer.SourceID(string(Timer), "", n)
		if last, ok := b.lastFired[src]; ok && !due.After(last) {
			continue
		}
		dueText := due.UTC().Format(time.RFC3339Nano)
		e := Event{
			ID:      b.keyer.ID("evt", string(Timer), "", n, dueText),
			Source:  src,
			Kind:    Timer,
			Ref:     b.scrub.Scrub(n),
			Version: dueText,
			At:      due,
			Label:   recall.EffectiveLabel(string(Timer), s.Label),
			Summary: b.scrub.Scrub(s.Summary),
		}
		if _, _, err := b.publishLocked(e); err != nil {
			return err
		}
		b.lastFired[src] = due
	}
	return nil
}

// Pump tries every pending (event, trigger) pair that is due, in publish
// order, and returns how many deliveries succeeded. Before each Start it
// re-checks, under the lock, that the delivery is still pending, so a
// deletion during Pump is not undone by a stale delivery. A failure is
// retried after a backoff (2s doubling, at most an hour).
func (b *Bus) Pump(ctx context.Context) int {
	type job struct {
		id, trigger string
	}
	b.mu.Lock()
	now := b.now()
	var jobs []job
	for _, id := range b.order {
		e := b.live[id]
		names := make([]string, 0, len(e.pending))
		for n := range e.pending {
			if t, ok := e.next[n]; !ok || !now.Before(t) {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		for _, n := range names {
			jobs = append(jobs, job{id, n})
		}
	}
	b.mu.Unlock()

	ok := 0
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		b.mu.Lock()
		e := b.live[j.id]
		if e == nil {
			b.mu.Unlock()
			continue
		}
		tries, still := e.pending[j.trigger]
		if !still {
			b.mu.Unlock()
			continue
		}
		d := Delivery{Key: j.id + "/" + j.trigger, Trigger: j.trigger, Attempt: tries + 1, Event: e.ev}
		t := b.triggers[j.trigger]
		b.mu.Unlock()

		err := safeStart(ctx, t, d)

		b.mu.Lock()
		e = b.live[j.id]
		if e == nil {
			b.mu.Unlock()
			continue
		}
		if _, still := e.pending[j.trigger]; !still {
			b.mu.Unlock()
			continue
		}
		var r record
		switch {
		case err == nil:
			r = record{Op: "ack", ID: j.id, Trigger: j.trigger}
			ok++
		case d.Attempt >= b.maxTries:
			r = record{Op: "dead", ID: j.id, Trigger: j.trigger}
		default:
			r = record{Op: "fail", ID: j.id, Trigger: j.trigger}
		}
		if aerr := b.append(r); aerr == nil {
			b.apply(r)
			switch r.Op {
			case "fail":
				back := 2 * time.Second << uint(d.Attempt-1)
				if back > time.Hour || back <= 0 {
					back = time.Hour
				}
				e.next[j.trigger] = b.now().Add(back)
			case "dead":
				if b.att != nil {
					b.att.Note(fmt.Sprintf("Couldn't act on a new %s item: %s failed %d times and won't try again.", d.Event.Kind, d.Trigger, d.Attempt))
				}
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

// Forget drops every event, pending or not, about a source (its keyed
// identity, as recall.Index.SourceID gives it) and rewrites the log, so a
// deletion reaches the bus's copy too (CAP-3). Event IDs stay in the seen
// list, so the same version is not delivered again.
func (b *Bus) Forget(source string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	hit := false
	for id, e := range b.live {
		if e.ev.Source == source {
			delete(b.live, id)
			hit = true
		}
	}
	if !hit && b.stale == 0 {
		return nil
	}
	b.reorder()
	return b.compact()
}

// ForgetSource adapts Forget to recall.Index.OnDelete.
func (b *Bus) ForgetSource(d recall.Deleted) error { return b.Forget(d.ID) }

func (b *Bus) append(r record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := b.log.Append(append(data, '\n')); err != nil {
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
		e := &entry{ev: *r.Event, pending: map[string]int{}, next: map[string]time.Time{}}
		for _, t := range r.Targets {
			e.pending[t] = 0
		}
		b.live[r.Event.ID] = e
		b.order = append(b.order, r.Event.ID)
		if r.Event.Kind == Timer {
			if t, err := time.Parse(time.RFC3339Nano, r.Event.Version); err == nil && t.After(b.lastFired[r.Event.Source]) {
				b.lastFired[r.Event.Source] = t
			}
		}
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
		if r.At.After(b.lastFired[r.Src]) {
			b.lastFired[r.Src] = r.At
		}
	}
}

// settle drops the content of events with no pending delivery.
func (b *Bus) settle() {
	changed := false
	for id, e := range b.live {
		if len(e.pending) == 0 {
			delete(b.live, id)
			b.stale++
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

func (b *Bus) maybeCompact() error {
	if b.stale >= staleLimit {
		return b.compact()
	}
	return nil
}

// compact rewrites the log with timer state and live events only. Its cost
// is proportional to live events, not to history.
func (b *Bus) compact() error {
	var buf []byte
	n := 0
	put := func(r record) error {
		data, err := json.Marshal(r)
		if err != nil {
			return err
		}
		buf = append(append(buf, data...), '\n')
		n++
		return nil
	}
	srcs := make([]string, 0, len(b.lastFired))
	for s := range b.lastFired {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	for _, s := range srcs {
		if err := put(record{Op: "timer", Src: s, At: b.lastFired[s]}); err != nil {
			return err
		}
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
		for _, t := range targets {
			for k := 0; k < e.pending[t]; k++ {
				if err := put(record{Op: "fail", ID: id, Trigger: t}); err != nil {
					return err
				}
			}
		}
	}
	if err := b.log.Rewrite(buf); err != nil {
		return err
	}
	b.lines = n
	b.stale = 0
	return nil
}

// IndexInto returns a trigger that records every event in the recall index
// with its provenance (CAP-3: everything the system has seen), under the
// event's source identity. ix must be the index whose Keyer the bus uses.
func IndexInto(ix *recall.Index) Trigger {
	return Trigger{
		Name: "recall",
		Start: func(_ context.Context, d Delivery) error {
			e := d.Event
			if recall.ReservedKinds[string(e.Kind)] {
				return fmt.Errorf("%w: %s", ErrReservedKind, e.Kind)
			}
			text := e.Summary
			if e.Body != "" {
				if text != "" {
					text += "\n"
				}
				text += e.Body
			}
			_, err := ix.IngestKeyed(e.Source, recall.Item{
				Source: recall.Source{Kind: string(e.Kind), Account: e.Account, Ref: e.Ref, Seen: e.At},
				Label:  e.Label,
				Text:   text,
			})
			if errors.Is(err, recall.ErrDeleted) {
				return nil // deleted meanwhile: nothing to index
			}
			return err
		},
	}
}
