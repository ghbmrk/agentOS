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
	lines int
}

type provRecord struct {
	Lineage string    `json:"l"`
	IDs     []string  `json:"ids,omitempty"`
	At      time.Time `json:"at,omitempty"`
	Forget  bool      `json:"forget,omitempty"` // drop IDs (or, with none, the lineage)
}

// OpenProvenance loads the record from store (a recall.FileStore in the
// broker's state directory; unreadable lines are skipped).
func OpenProvenance(store recall.Store) (*Provenance, error) {
	p := &Provenance{store: store, sets: map[string]map[string]time.Time{}}
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
		if _, ok := s[id]; !ok {
			s[id] = r.At
		}
	}
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
		if _, ok := p.sets[lineage][id]; !ok && id != "" {
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
	if err := p.store.Rewrite(buf); err != nil {
		return err
	}
	p.lines = n
	return nil
}

// ForgetSince drops what lineage was given at or after since: its machines
// went back to before then, so it no longer holds those items.
func (p *Provenance) ForgetSince(lineage string, since time.Time) error {
	p.mu.Lock()
	var ids []string
	for id, t := range p.sets[lineage] {
		if !t.Before(since) {
			ids = append(ids, id)
		}
	}
	p.mu.Unlock()
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids)
	return p.Forget(lineage, ids...)
}
