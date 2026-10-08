package recalltool

import (
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/recall"
)

// Provenance records which recall items each fork lineage has been given
// (K2b). A lineage shares its memory across forks and merges, so what one
// machine of it read, all of it may hold. Agent notes take their
// DerivedFrom from here, so deleting a source deletes what was made after
// it was read, and the deletion hooks find the lineages whose memory and
// snapshots hold it. A record is durable before the result it covers is
// returned.
type Provenance struct {
	mu    sync.Mutex
	store recall.Store
	sets  map[string]map[string]time.Time // lineage -> item ID -> first given
	// resets: lineages whose machines went back to before since, whose
	// reach is not finished (Reach), by since in UnixNano.
	resets map[string]map[int64]Reset
	// takeBacks: approved take-backs of a lineage from since (UnixNano),
	// true once its machines went back (W3-forget-b2b, #327 L3).
	takeBacks map[string]map[int64]bool
	lines     int
}

type provRecord struct {
	Lineage string    `json:"l"`
	IDs     []string  `json:"ids,omitempty"`
	At      time.Time `json:"at,omitempty"`
	Forget  bool      `json:"forget,omitempty"` // drop IDs (or, with none, the lineage)
	// Reset, with At: the lineage's machines went back to before At at
	// Reset. With Forget, the reach from At is done: IDs are dropped and
	// the mark goes.
	Reset time.Time `json:"reset,omitempty"`
	// Until, with Reset: when the machines were all back.
	Until time.Time `json:"until,omitempty"`
	// TakeBack, with At: a take-back of the lineage from At is owed; with
	// Forget, done. A reset from At also marks an owed one done.
	TakeBack bool `json:"tb,omitempty"`
}

// OpenProvenance loads the record from store (a recall.FileStore in the
// broker's state directory; unreadable lines are skipped).
func OpenProvenance(store recall.Store) (*Provenance, error) {
	p := &Provenance{store: store, sets: map[string]map[string]time.Time{}, resets: map[string]map[int64]Reset{}, takeBacks: map[string]map[int64]bool{}}
	data, err := store.ReadAll()
	if err != nil {
		return nil, err
	}
	lines, torn := recall.Lines(data)
	for _, l := range lines {
		var r provRecord
		if json.Unmarshal(l, &r) == nil {
			p.apply(r)
		}
	}
	p.lines = len(lines)
	if torn {
		if err := p.compact(); err != nil {
			return nil, err
		}
	}
	return p, nil
}

func (p *Provenance) apply(r provRecord) {
	if r.Lineage == "" {
		return
	}
	if r.TakeBack {
		since := r.At.UnixNano()
		if p.takeBacks[r.Lineage] == nil {
			p.takeBacks[r.Lineage] = map[int64]bool{}
		}
		if done, ok := p.takeBacks[r.Lineage][since]; !ok || !done {
			p.takeBacks[r.Lineage][since] = r.Forget
		}
		return
	}
	if !r.Reset.IsZero() {
		since := r.At.UnixNano()
		if r.Forget {
			for _, id := range r.IDs {
				delete(p.sets[r.Lineage], id)
			}
			delete(p.resets[r.Lineage], since)
			if len(p.resets[r.Lineage]) == 0 {
				delete(p.resets, r.Lineage)
			}
			return
		}
		if _, ok := p.takeBacks[r.Lineage][since]; ok {
			p.takeBacks[r.Lineage][since] = true
		}
		if p.resets[r.Lineage] == nil {
			p.resets[r.Lineage] = map[int64]Reset{}
		}
		until := r.Until
		if until.IsZero() {
			until = r.Reset
		}
		p.resets[r.Lineage][since] = Reset{Since: r.At.UTC(), At: r.Reset.UTC(), Until: until.UTC()}
		return
	}
	if r.Forget {
		if len(r.IDs) == 0 {
			delete(p.sets, r.Lineage)
			return
		}
		for _, id := range r.IDs {
			delete(p.sets[r.Lineage], id)
		}
		return
	}
	s := p.sets[r.Lineage]
	if s == nil {
		s = map[string]time.Time{}
		p.sets[r.Lineage] = s
	}
	for _, id := range r.IDs {
		if t, ok := s[id]; !ok || p.undone(r.Lineage, t) {
			s[id] = r.At
		}
	}
}

// undone reports a time inside an unfinished reset of lineage: what was
// given then is no longer in its machines, so giving it again is new
// (#59 L3 re-review 1). Called with mu held, or while loading.
func (p *Provenance) undone(lineage string, t time.Time) bool {
	for _, rs := range p.resets[lineage] {
		if !t.Before(rs.Since) && t.Before(rs.At) {
			return true
		}
	}
	return false
}

func (p *Provenance) write(r provRecord) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := p.store.Append(append(b, '\n')); err != nil {
		return err
	}
	p.lines++
	p.apply(r)
	return nil
}

// Given records that lineage was given ids at time at.
func (p *Provenance) Given(lineage string, ids []string, at time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var fresh []string
	for _, id := range ids {
		if t, ok := p.sets[lineage][id]; (!ok || p.undone(lineage, t)) && id != "" {
			fresh = append(fresh, id)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	return p.write(provRecord{Lineage: lineage, IDs: fresh, At: at})
}

// Of returns the IDs lineage was given, sorted.
func (p *Provenance) Of(lineage string) []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.sets[lineage]))
	for id := range p.sets[lineage] {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Holders returns the lineages given id and when each first was.
func (p *Provenance) Holders(id string) map[string]time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]time.Time{}
	for l, s := range p.sets {
		if t, ok := s[id]; ok {
			out[l] = t
		}
	}
	return out
}

// Forget drops ids from lineage's record, or the whole lineage when ids is
// empty (its memory and snapshots no longer hold them).
func (p *Provenance) Forget(lineage string, ids ...string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.write(provRecord{Lineage: lineage, IDs: ids, Forget: true}); err != nil {
		return err
	}
	live := 0
	for _, s := range p.sets {
		live += len(s)
	}
	if p.lines > 64 && p.lines > 2*(len(p.sets)+live/64+1) {
		return p.compact()
	}
	return nil
}

func (p *Provenance) compact() error {
	ls := make([]string, 0, len(p.sets))
	for l := range p.sets {
		ls = append(ls, l)
	}
	sort.Strings(ls)
	var buf []byte
	n := 0
	for _, l := range ls {
		byTime := map[time.Time][]string{}
		for id, t := range p.sets[l] {
			byTime[t] = append(byTime[t], id)
		}
		for t, ids := range byTime {
			sort.Strings(ids)
			b, err := json.Marshal(provRecord{Lineage: l, IDs: ids, At: t})
			if err != nil {
				return err
			}
			buf = append(append(buf, b...), '\n')
			n++
		}
	}
	for _, l := range sortedKeys(p.resets) {
		for _, rs := range p.resets[l] {
			b, err := json.Marshal(provRecord{Lineage: l, At: rs.Since, Reset: rs.At, Until: rs.Until})
			if err != nil {
				return err
			}
			buf = append(append(buf, b...), '\n')
			n++
		}
	}
	for _, l := range sortedKeys(p.takeBacks) {
		for since, done := range p.takeBacks[l] {
			b, err := json.Marshal(provRecord{Lineage: l, At: time.Unix(0, since).UTC(), TakeBack: true, Forget: done})
			if err != nil {
				return err
			}
			buf = append(append(buf, b...), '\n')
			n++
		}
	}
	if err := p.store.Rewrite(buf); err != nil {
		return err
	}
	p.lines = n
	return nil
}

// Items returns what lineage was given and when each first was.
func (p *Provenance) Items(lineage string) map[string]time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]time.Time, len(p.sets[lineage]))
	for id, t := range p.sets[lineage] {
		out[id] = t
	}
	return out
}

// Reset is a lineage whose machines went back to before Since: the reset
// began at At and the last machine was back at Until. Its reach is not
// yet finished.
type Reset struct{ Since, At, Until time.Time }

// MarkReset records, durably, that lineage's machines went back to before
// rs.Since: a reach finished later (or after a restart) forgets only what
// was given from Since until At, and does not reset the machines again.
func (p *Provenance) MarkReset(lineage string, rs Reset) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.write(provRecord{Lineage: lineage, At: rs.Since.UTC(), Reset: rs.At.UTC(), Until: rs.Until.UTC()})
}

// Resets lists lineage's unfinished resets, oldest first.
func (p *Provenance) Resets(lineage string) []Reset {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Reset
	for _, rs := range p.resets[lineage] {
		out = append(out, rs)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since.Before(out[j].Since) })
	return out
}

// ResetLineages lists the lineages with an unfinished reset.
func (p *Provenance) ResetLineages() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return sortedKeys(p.resets)
}

// MarkTakeBack records, durably, an approved take-back of lineage from
// since: owed until done, so a restart does not lose it, and done once its
// machines went back, so it is never repeated (vm.ForgetSince).
func (p *Provenance) MarkTakeBack(lineage string, since time.Time, done bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.write(provRecord{Lineage: lineage, At: since.UTC(), TakeBack: true, Forget: done})
}

// TakeBack reports whether a take-back of lineage from since is recorded,
// and whether it is done.
func (p *Provenance) TakeBack(lineage string, since time.Time) (recorded, done bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	done, recorded = p.takeBacks[lineage][since.UTC().UnixNano()]
	return recorded, done
}

// OwedTakeBack is an approved take-back not yet done.
type OwedTakeBack struct {
	Lineage string
	Since   time.Time
}

// TakeBacksOwed lists the take-backs not yet done, by lineage and since.
func (p *Provenance) TakeBacksOwed() []OwedTakeBack {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []OwedTakeBack
	for _, l := range sortedKeys(p.takeBacks) {
		var ss []int64
		for since, done := range p.takeBacks[l] {
			if !done {
				ss = append(ss, since)
			}
		}
		sort.Slice(ss, func(i, j int) bool { return ss[i] < ss[j] })
		for _, since := range ss {
			out = append(out, OwedTakeBack{Lineage: l, Since: time.Unix(0, since).UTC()})
		}
	}
	return out
}

// Finish ends the reach of a reset: what lineage was given from r.Since
// until r.At is dropped (its machines went back to before then); what it
// was given after the reset stays (#59 L3 2). The mark goes with it.
func (p *Provenance) Finish(lineage string, r Reset) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var ids []string
	for id, t := range p.sets[lineage] {
		if !t.Before(r.Since) && t.Before(r.At) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return p.write(provRecord{Lineage: lineage, IDs: ids, At: r.Since.UTC(), Reset: r.At.UTC(), Forget: true})
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
