package recalltool

import (
	"encoding/json"
	"errors"
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
	// backs: take-backs whose machines went back by the Reset whose
	// recording failed (errUnrecorded), by since: Retry records and
	// finishes it without resetting the machines again (RCH-2).
	backs map[string]map[int64]Reset
	// Anchors (W3): a lineage's reads are summed into a chain of anchor
	// items, each derived from the one before and from what was read since,
	// so a note derives from one item whatever the lineage has read.
	// anchor is the newest; covered the IDs it stands for (its chain holds
	// them); anchors counts those made (it numbers them); chainLen is how
	// many the current chain holds, for its rebuild; gen changes when the
	// chain is dropped.
	anchor   map[string]string
	covered  map[string]map[string]bool
	anchors  map[string]int
	chainLen map[string]int
	gen      map[string]int
	notes    map[string]map[string]bool // lineage -> note keys made
	lines    int
	limits   Limits

	anchorMu sync.Mutex // one anchoring at a time; never held by hooks
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
	// Forget, done. A reset from At also marks an owed one done. With
	// Forget and Reset (and Until), done by a reset not yet recorded.
	TakeBack bool `json:"tb,omitempty"`
	// Anchor, with IDs: the anchor item Anchor now stands for the lineage's
	// reads, IDs being those it added to its chain. Seq counts the lineage's
	// anchors made (an anchor-less record keeps the count).
	Anchor string `json:"a,omitempty"`
	Seq    int    `json:"seq,omitempty"`
	// Collapse, with Anchor: the anchor starts a chain and stands for IDs
	// alone (it derives from the reads, not the anchor before); Chain is
	// the chain's length (compaction; 0 means 1).
	Collapse bool `json:"c,omitempty"`
	Chain    int  `json:"ch,omitempty"`
	// Note: a note key the lineage made; with Forget, one that is gone.
	Note string `json:"n,omitempty"`
}

// OpenProvenance loads the record from store (a recall.FileStore in the
// broker's state directory; unreadable lines are skipped).
func OpenProvenance(store recall.Store) (*Provenance, error) {
	p := &Provenance{store: store, sets: map[string]map[string]time.Time{}, resets: map[string]map[int64]Reset{}, takeBacks: map[string]map[int64]bool{}, backs: map[string]map[int64]Reset{},
		anchor: map[string]string{}, covered: map[string]map[string]bool{}, anchors: map[string]int{}, chainLen: map[string]int{}, gen: map[string]int{}, notes: map[string]map[string]bool{}}
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
	if r.Note != "" {
		if r.Forget {
			delete(p.notes[r.Lineage], r.Note)
		} else {
			if p.notes[r.Lineage] == nil {
				p.notes[r.Lineage] = map[string]bool{}
			}
			p.notes[r.Lineage][r.Note] = true
		}
		return
	}
	if r.Seq > 0 || r.Anchor != "" {
		if r.Seq > p.anchors[r.Lineage] {
			p.anchors[r.Lineage] = r.Seq
		}
		if r.Anchor != "" {
			p.anchor[r.Lineage] = r.Anchor
			if r.Collapse || p.covered[r.Lineage] == nil {
				p.covered[r.Lineage] = map[string]bool{}
			}
			switch {
			case r.Chain > 0:
				p.chainLen[r.Lineage] = r.Chain
			case r.Collapse:
				p.chainLen[r.Lineage] = 1
			default:
				p.chainLen[r.Lineage]++
			}
			for _, id := range r.IDs {
				p.covered[r.Lineage][id] = true
			}
		}
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
		if r.Forget && !r.Reset.IsZero() {
			if p.backs[r.Lineage] == nil {
				p.backs[r.Lineage] = map[int64]Reset{}
			}
			p.backs[r.Lineage][since] = resetOf(r)
		}
		return
	}
	if !r.Reset.IsZero() {
		since := r.At.UnixNano()
		if r.Forget {
			p.drop(r.Lineage, r.IDs)
			delete(p.resets[r.Lineage], since)
			if len(p.resets[r.Lineage]) == 0 {
				delete(p.resets, r.Lineage)
			}
			return
		}
		if _, ok := p.takeBacks[r.Lineage][since]; ok {
			p.takeBacks[r.Lineage][since] = true
		}
		delete(p.backs[r.Lineage], since)
		if len(p.backs[r.Lineage]) == 0 {
			delete(p.backs, r.Lineage)
		}
		if p.resets[r.Lineage] == nil {
			p.resets[r.Lineage] = map[int64]Reset{}
		}
		p.resets[r.Lineage][since] = resetOf(r)
		return
	}
	if r.Forget {
		if len(r.IDs) == 0 {
			delete(p.sets, r.Lineage)
			p.dropChain(r.Lineage)
			return
		}
		p.drop(r.Lineage, r.IDs)
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

// drop removes ids from lineage's reads. An anchor chain that stands for
// one of them is dropped whole, so the next note starts a chain from what
// is still held and derives from nothing forgotten.
func (p *Provenance) drop(lineage string, ids []string) {
	p.gen[lineage]++
	for _, id := range ids {
		delete(p.sets[lineage], id)
		if p.covered[lineage][id] {
			p.dropChain(lineage)
		}
	}
}

func (p *Provenance) dropChain(lineage string) {
	delete(p.anchor, lineage)
	delete(p.covered, lineage)
	delete(p.chainLen, lineage)
	p.gen[lineage]++
}

// resetOf is the Reset a reset or back record holds.
func resetOf(r provRecord) Reset {
	until := r.Until
	if until.IsZero() {
		until = r.Reset
	}
	return Reset{Since: r.At.UTC(), At: r.Reset.UTC(), Until: until.UTC()}
}

// undone reports a time inside an unfinished reset of lineage, recorded
// or not: what was given then is no longer in its machines, so giving it
// again is new (#59 L3 re-review 1). Called with mu held, or while
// loading.
func (p *Provenance) undone(lineage string, t time.Time) bool {
	for _, m := range []map[int64]Reset{p.resets[lineage], p.backs[lineage]} {
		for _, rs := range m {
			if !t.Before(rs.Since) && t.Before(rs.At) {
				return true
			}
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
	p.maybeCompact()
	return nil
}

// maybeCompact rewrites the record when it holds far more lines than the
// state it stands for, so no write path (a refused or repeated record
// included) grows the file without end. Best effort: a failed rewrite
// leaves the record as it was. Called with mu held.
func (p *Provenance) maybeCompact() {
	live := 0
	for _, s := range p.sets {
		live += len(s)
	}
	notes := 0
	for _, n := range p.notes {
		notes += len(n)
	}
	if p.lines > 64 && p.lines > 2*(len(p.sets)+live/64+notes+len(p.anchors)+1) {
		_ = p.compact()
	}
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
	for _, l := range sortedKeys(p.anchors) {
		var ids []string
		for id := range p.covered[l] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		b, err := json.Marshal(provRecord{Lineage: l, Anchor: p.anchor[l], IDs: ids, Seq: p.anchors[l], Collapse: p.anchor[l] != "", Chain: p.chainLen[l]})
		if err != nil {
			return err
		}
		buf = append(append(buf, b...), '\n')
		n++
	}
	for _, l := range sortedKeys(p.notes) {
		for _, k := range sortedKeys(p.notes[l]) {
			b, err := json.Marshal(provRecord{Lineage: l, Note: k})
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
	for _, l := range sortedKeys(p.backs) {
		for _, rs := range p.backs[l] {
			b, err := json.Marshal(provRecord{Lineage: l, At: rs.Since, Reset: rs.At, Until: rs.Until, TakeBack: true, Forget: true})
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
// machines went back, so it is never repeated (vm.ForgetSince). Done is
// kept in memory even when it cannot be written, so this run never repeats
// it (#327 L3 re-review); only a restart before a write lands can.
func (p *Provenance) MarkTakeBack(lineage string, since time.Time, done bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := provRecord{Lineage: lineage, At: since.UTC(), TakeBack: true, Forget: done}
	err := p.write(r)
	if err != nil && done {
		p.apply(r)
	}
	return err
}

// TakeBack reports whether a take-back of lineage from since is recorded,
// and whether it is done.
func (p *Provenance) TakeBack(lineage string, since time.Time) (recorded, done bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	done, recorded = p.takeBacks[lineage][since.UTC().UnixNano()]
	return recorded, done
}

// MarkBack records, durably, that an approved or unasked take-back of
// lineage went back by rs but MarkReset did not record it (RCH-2): the
// take-back is done, so its machines never go back again, and its reach
// is owed until Retry records the reset (MarkReset) and finishes it. Kept
// in memory even when it cannot be written, as MarkTakeBack's done.
func (p *Provenance) MarkBack(lineage string, rs Reset) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	r := provRecord{Lineage: lineage, At: rs.Since.UTC(), Reset: rs.At.UTC(), Until: rs.Until.UTC(), TakeBack: true, Forget: true}
	err := p.write(r)
	if err != nil {
		p.apply(r)
	}
	return err
}

// Back is a lineage whose machines went back by Reset, not yet recorded.
type Back struct {
	Lineage string
	Reset
}

// Backs lists the take-backs whose machines went back by a reset not yet
// recorded (MarkBack), by lineage and since.
func (p *Provenance) Backs() []Back {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Back
	for _, l := range sortedKeys(p.backs) {
		for _, rs := range p.backs[l] {
			out = append(out, Back{Lineage: l, Reset: rs})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Lineage != out[j].Lineage {
			return out[i].Lineage < out[j].Lineage
		}
		return out[i].Since.Before(out[j].Since)
	})
	return out
}

// TakeBackState is where a take-back from a time stands (RCH-1).
type TakeBackState int

const (
	// TakeBackNone: no take-back or reset from that time is recorded.
	TakeBackNone TakeBackState = iota
	// TakeBackOwed: recorded and not done, or its machines are back but
	// the reset is unrecorded or its reach unfinished; Retry carries it.
	TakeBackOwed
	// TakeBackDone: its machines are back and the reset is recorded and
	// finished.
	TakeBackDone
)

// TakeBackOf reports where a take-back from since stands, on any lineage
// (as TakenBackFrom): owed while any take-back or reset from since is not
// finished, done once one is and none is left.
func (p *Provenance) TakeBackOf(since time.Time) TakeBackState {
	p.mu.Lock()
	defer p.mu.Unlock()
	at := since.UTC().UnixNano()
	for _, m := range []map[string]map[int64]Reset{p.resets, p.backs} {
		for _, rs := range m {
			if _, ok := rs[at]; ok {
				return TakeBackOwed
			}
		}
	}
	st := TakeBackNone
	for _, m := range p.takeBacks {
		if done, ok := m[at]; ok && !done {
			return TakeBackOwed
		} else if ok {
			st = TakeBackDone
		}
	}
	return st
}

// TakeBacksNotDone lists the take-backs whose TakeBackOf is not done, by
// lineage and since.
func (p *Provenance) TakeBacksNotDone() []OwedTakeBack {
	var out []OwedTakeBack
	p.mu.Lock()
	for _, l := range sortedKeys(p.takeBacks) {
		for since := range p.takeBacks[l] {
			out = append(out, OwedTakeBack{Lineage: l, Since: time.Unix(0, since).UTC()})
		}
	}
	p.mu.Unlock()
	kept := out[:0]
	for _, tb := range out {
		if p.TakeBackOf(tb.Since) != TakeBackDone {
			kept = append(kept, tb)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Since.Before(kept[j].Since) })
	return kept
}

// TakenBackFrom reports whether a take-back from since, owed or done,
// or a reset from since is recorded on any lineage: a task's time names
// one take-back, whichever lineage the agent machine has now.
func (p *Provenance) TakenBackFrom(since time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	at := since.UTC().UnixNano()
	for _, m := range p.takeBacks {
		if _, ok := m[at]; ok {
			return true
		}
	}
	for _, m := range p.resets {
		if _, ok := m[at]; ok {
			return true
		}
	}
	return false
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

// Limits bound what one guest, and all of them, can make the broker keep
// for recall notes (W3). A note past a limit is refused before anything is
// stored.
type Limits struct {
	Notes, NotesAll int // note keys per lineage, and in all
	Reads, ReadsAll int // items a lineage has read, and in all
	// Anchors is how many anchors a chain holds before the next one starts
	// a new chain from the reads, so a chain stays short.
	Anchors int
}

// DefaultLimits keeps a lineage to 1000 notes and 20,000 read items, the
// broker to ten times each, and a chain to 64 anchors.
var DefaultLimits = Limits{Notes: 1000, NotesAll: 10000, Reads: 20000, ReadsAll: 200000, Anchors: 64}

// ErrLimit means a note was refused for a limit.
var ErrLimit = errors.New("recalltool: provenance limit reached")

// SetLimits replaces the limits (zero fields keep the defaults).
func (p *Provenance) SetLimits(l Limits) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := DefaultLimits
	for _, f := range []struct {
		dst *int
		v   int
	}{{&d.Notes, l.Notes}, {&d.NotesAll, l.NotesAll}, {&d.Reads, l.Reads}, {&d.ReadsAll, l.ReadsAll}, {&d.Anchors, l.Anchors}} {
		if f.v > 0 {
			*f.dst = f.v
		}
	}
	p.limits = d
}

func (p *Provenance) lim() Limits {
	if p.limits == (Limits{}) {
		return DefaultLimits
	}
	return p.limits
}

func sum[V any](m map[string]V, n func(V) int) int {
	t := 0
	for _, v := range m {
		t += n(v)
	}
	return t
}

// Check refuses (ErrLimit) a note of lineage with key that a limit does not
// allow, and writes nothing for it. exists says whether a note key still has
// its item: at a limit, keys whose items are gone are forgotten first, so
// deleted notes free their place. Called before anything is stored; the
// caller records the key with Noted once the note is stored.
func (p *Provenance) Check(lineage, key string, exists func(lineage, key string) bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	lm := p.lim()
	if len(p.sets[lineage]) > lm.Reads || sum(p.sets, func(s map[string]time.Time) int { return len(s) }) > lm.ReadsAll {
		return ErrLimit
	}
	if p.notes[lineage][key] {
		return nil
	}
	count := func(m map[string]bool) int { return len(m) }
	if len(p.notes[lineage]) >= lm.Notes || sum(p.notes, count) >= lm.NotesAll {
		for _, l := range sortedKeys(p.notes) {
			for _, k := range sortedKeys(p.notes[l]) {
				if !exists(l, k) {
					if err := p.write(provRecord{Lineage: l, Note: k, Forget: true}); err != nil {
						return err
					}
				}
			}
		}
		if len(p.notes[lineage]) >= lm.Notes || sum(p.notes, count) >= lm.NotesAll {
			return ErrLimit
		}
	}
	return nil
}

// Noted records, durably, that lineage stored a note with key.
func (p *Provenance) Noted(lineage, key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.notes[lineage][key] {
		return nil
	}
	return p.write(provRecord{Lineage: lineage, Note: key})
}

// Head reports whether id is the newest anchor of a lineage's chain. Its
// tombstone must outlive the prune policy (Reach.Needed): the next anchor
// derives from it, and is refused while it is deleted.
func (p *Provenance) Head(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, a := range p.anchor {
		if a == id {
			return true
		}
	}
	return false
}

// Anchor returns what a note of lineage derives from: one anchor item that
// stands for everything the lineage has read, none when it has read
// nothing. Reads since the last anchor, with that anchor, go into a new one
// that mk builds (it returns the item's ID); the note's cost does not
// grow with the lineage's history, and deleting any source read deletes the
// anchors that follow it and so the notes (K2b, recall R6). When the chain
// reaches its length limit, the new anchor derives from all the reads
// instead and starts a chain: the chain stays short, and the older anchors,
// with the notes made on them, keep what they derived from.
func (p *Provenance) Anchor(lineage string, mk func(seq int, derived []string) (string, error)) ([]string, error) {
	p.anchorMu.Lock()
	defer p.anchorMu.Unlock()
	p.mu.Lock()
	var delta, all []string
	for id := range p.sets[lineage] {
		all = append(all, id)
		if !p.covered[lineage][id] {
			delta = append(delta, id)
		}
	}
	prev, gen, made := p.anchor[lineage], p.gen[lineage], p.anchors[lineage]
	collapse := prev != "" && p.chainLen[lineage] >= p.lim().Anchors
	p.mu.Unlock()
	if len(delta) == 0 {
		if prev == "" {
			return nil, nil
		}
		return []string{prev}, nil
	}
	sort.Strings(delta)
	derived := delta
	switch {
	case collapse:
		sort.Strings(all)
		derived, delta = all, all
	case prev != "":
		derived = append([]string{prev}, delta...)
	}
	id, err := mk(made+1, derived)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gen[lineage] != gen {
		return nil, errChanged
	}
	if err := p.write(provRecord{Lineage: lineage, Anchor: id, IDs: delta, Seq: made + 1, Collapse: collapse || prev == ""}); err != nil {
		return nil, err
	}
	return []string{id}, nil
}

var errChanged = errors.New("recalltool: provenance changed while anchoring")

// Size reports what recall provenance keeps for lineage: items read, note
// keys and anchors made.
func (p *Provenance) Size(lineage string) (reads, notes, anchors int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.sets[lineage]), len(p.notes[lineage]), p.anchors[lineage]
}
