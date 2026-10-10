// Package projection rebuilds views of the journal (inbox, digest, pacing,
// hold, learning statistics, attention) as pure functions of its records
// (SIM-proj, D-095).
//
// The journal is the only durable source of truth. A projection may save a
// snapshot of itself with the journal sequence number it reflects, so boot
// can restore the latest snapshot and replay only the tail; a snapshot that
// is missing, damaged, from another journal or refused by Restore is
// ignored and the projection is rebuilt from the first record (OP-4).
// Snapshots are caches: deleting all of them changes nothing but boot time.
//
// Projections are untrusted: nothing here is read by the journal engine,
// and a projection's state never decides authority, a grant or a dispatch.
package projection

import (
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Projection is a view rebuilt from journal records.
//
// Apply must be deterministic and depend only on the records applied so
// far, so a snapshot plus the tail reaches the same state as a replay from
// empty. On a journal.RecErased record it must drop everything it holds
// that was derived from that intent's content (CAP-3): replay from empty
// reads the erased records already scrubbed, so a projection that keeps
// erased content also breaks the snapshot-plus-tail equality.
//
// Restore(nil, 0) resets to empty. Restore(data, offset) loads a Snapshot
// taken after applying records 1..offset; it returns an error if data is
// unusable, and the caller then resets and replays in full.
type Projection interface {
	Name() string
	Apply(journal.Record)
	Snapshot() ([]byte, error)
	Restore(data []byte, offset uint64) error
}

// Source is the journal as a projection reads it. *journal.Engine is one.
type Source interface {
	RecordsAfter(seq uint64) []journal.Record
}

// Store keeps at most one snapshot per projection name.
type Store interface {
	// Load returns the stored snapshot, or an error wrapping
	// fs.ErrNotExist when there is none.
	Load(name string) ([]byte, error)
	// Save replaces the stored snapshot atomically.
	Save(name string, data []byte) error
	// Delete removes the stored snapshot; a missing one is not an error.
	Delete(name string) error
}

// Boot reports, per projection, the sequence number its restored snapshot
// reflected (0 when it replayed from empty) and why a stored snapshot was
// not used.
type Boot struct {
	Name     string
	From     uint64
	Fallback string
}

// Report is the boot report, one entry per projection in New's order.
type Report []Boot

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// Projector keeps projections current with the journal and snapshots them.
// It is safe for concurrent use; projections are applied under its lock.
type Projector struct {
	mu    sync.Mutex
	store Store
	every uint64
	views []*view
}

type view struct {
	p      Projection
	offset uint64 // records 1..offset applied
	snapAt uint64 // offset of the last saved snapshot
	anchor string // anchor of record offset
	purge  bool   // an erase was applied since the stored snapshot was saved
}

// New returns a projector that snapshots each projection after every
// `every` records it applies. Names must be distinct, lower-case file-safe
// tokens.
func New(store Store, every uint64, ps ...Projection) (*Projector, error) {
	if every == 0 {
		return nil, errors.New("projection: snapshot period must be at least 1")
	}
	pr := &Projector{store: store, every: every}
	seen := map[string]bool{}
	for _, p := range ps {
		n := p.Name()
		if !nameRE.MatchString(n) || seen[n] {
			return nil, fmt.Errorf("projection: bad or duplicate name %q", n)
		}
		seen[n] = true
		pr.views = append(pr.views, &view{p: p})
	}
	return pr, nil
}

// Boot restores each projection from its latest usable snapshot and
// replays the journal tail after it, or replays from empty. It returns the
// report and any error saving a snapshot; a failed save leaves every
// projection current.
func (pr *Projector) Boot(src Source) (Report, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	rep := make(Report, len(pr.views))
	var errs []error
	for i, v := range pr.views {
		from, tail, why := pr.restore(v, src)
		if why != "" {
			if err := v.p.Restore(nil, 0); err != nil {
				return nil, fmt.Errorf("projection %s: reset: %w", v.p.Name(), err)
			}
			from, tail, v.anchor = 0, src.RecordsAfter(0), ""
		}
		v.offset, v.snapAt, v.purge = from, from, false
		rep[i] = Boot{Name: v.p.Name(), From: from, Fallback: why}
		errs = append(errs, pr.apply(v, tail))
	}
	return rep, errors.Join(errs...)
}

// restore loads v's snapshot and returns its offset and the records after
// it, or a reason it cannot be used. "" with offset 0 means no snapshot.
func (pr *Projector) restore(v *view, src Source) (uint64, []journal.Record, string) {
	v.anchor = ""
	b, err := pr.store.Load(v.p.Name())
	if err != nil {
		if isNotExist(err) {
			return 0, src.RecordsAfter(0), ""
		}
		return 0, nil, "load: " + err.Error()
	}
	h, data, err := decode(b)
	if err != nil {
		return 0, nil, err.Error()
	}
	if h.Name != v.p.Name() {
		return 0, nil, fmt.Sprintf("snapshot names %q", h.Name)
	}
	if h.Seq == 0 {
		return 0, nil, "snapshot at offset 0"
	}
	recs := src.RecordsAfter(h.Seq - 1)
	if len(recs) == 0 {
		return 0, nil, fmt.Sprintf("snapshot at %d is beyond the journal", h.Seq)
	}
	if anchor(recs[0]) != h.Anchor {
		return 0, nil, fmt.Sprintf("snapshot at %d does not match the journal record there", h.Seq)
	}
	if err := v.p.Restore(data, h.Seq); err != nil {
		return 0, nil, "restore: " + err.Error()
	}
	v.anchor = h.Anchor
	return h.Seq, recs[1:], ""
}

// Sync applies the records written since the last Sync or Boot and saves
// snapshots that are due.
func (pr *Projector) Sync(src Source) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	var errs []error
	for _, v := range pr.views {
		errs = append(errs, pr.apply(v, src.RecordsAfter(v.offset)))
	}
	return errors.Join(errs...)
}

// SnapshotNow saves a snapshot of every projection at its current offset.
func (pr *Projector) SnapshotNow() error {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	var errs []error
	for _, v := range pr.views {
		if v.offset > 0 {
			errs = append(errs, pr.save(v))
		}
	}
	return errors.Join(errs...)
}

func (pr *Projector) apply(v *view, recs []journal.Record) error {
	for _, r := range recs {
		if r.Seq != v.offset+1 {
			return fmt.Errorf("projection %s: record %d after %d", v.p.Name(), r.Seq, v.offset)
		}
		v.p.Apply(r)
		v.offset, v.anchor = r.Seq, anchor(r)
		if r.Type == journal.RecErased {
			v.purge = true
		}
	}
	if v.offset == 0 || !(v.purge || v.offset-v.snapAt >= pr.every) {
		return nil
	}
	return pr.save(v)
}

// save writes v's snapshot at its current offset. If the write fails while
// the stored copy predates an erase, the stored copy is deleted instead, so
// no snapshot outlives an erase it does not reflect (CAP-3).
func (pr *Projector) save(v *view) error {
	data, err := v.p.Snapshot()
	if err == nil {
		var b []byte
		if b, err = encode(header{V: snapVersion, Name: v.p.Name(), Seq: v.offset, Anchor: v.anchor}, data); err == nil {
			err = pr.store.Save(v.p.Name(), b)
		}
	}
	if err != nil {
		if v.purge {
			if derr := pr.store.Delete(v.p.Name()); derr != nil {
				err = errors.Join(err, derr)
			} else {
				v.purge = false
			}
		}
		return fmt.Errorf("projection %s: snapshot: %w", v.p.Name(), err)
	}
	v.snapAt, v.purge = v.offset, false
	return nil
}
