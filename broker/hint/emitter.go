package hint

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Mode is the owner's policy for one category (OSS-7).
type Mode int

const (
	Automatic Mode = iota // the default: content crossing is clean-room
	Ask                   // ask the owner each time
	Never                 // keep on the box; still logged
)

const (
	// DefaultDailyLimit is the most hints one daily batch may carry when
	// Config.DailyLimit is zero.
	DefaultDailyLimit = 20
	// DefaultReleaseAt is the UTC time of day a batch is released when
	// Config.ReleaseAt is zero.
	DefaultReleaseAt = 4 * time.Hour
)

// ErrNoPending is returned when an ID names no hint waiting for the owner.
var ErrNoPending = errors.New("hint: no such pending hint")

// Outbox receives each day's batch of canonical hints for the clean-room
// builder, sorted.
type Outbox interface {
	Send(batch [][]byte) error
}

// Config sets up an Emitter.
type Config struct {
	Schema *Schema         // nil means Default()
	Policy map[string]Mode // by category; absent means Automatic

	// DailyLimit caps one batch (0 means DefaultDailyLimit). EmbargoReserve
	// of its slots are kept for embargo kinds such as vuln (0 means a
	// quarter of the limit, at least 1); slots one class leaves unused go
	// to the other. Hints over the cap wait for the next batch.
	DailyLimit     int
	EmbargoReserve int
	// MaxBacklog bounds the hints of each class waiting to cross (0 means
	// 7 × DailyLimit). Over it, a hint is logged OverLimit and dropped.
	MaxBacklog int
	// ReleaseAt is the UTC time of day after which the previous days'
	// hints are released (0 means DefaultReleaseAt).
	ReleaseAt time.Duration

	Log    Log    // required
	Outbox Outbox // required
	Now    func() time.Time
}

// Result says what Emit did. ID is set for an Asked hint and is what the
// owner's Approve or Decline names; it never crosses the bridge.
type Result struct {
	Outcome Outcome
	ID      int
}

// Pending is a hint waiting for the owner.
type Pending struct {
	ID     int
	Day    string
	Kind   string
	Fields map[string]string
}

type queued struct {
	seq     int
	day     string
	embargo bool
	canon   string
}

// Emitter is the private side's single exit to the bridge.
//
// Emit never sends. It queues a hint (or asks the owner about it), and
// Release, called on any schedule, sends every hint queued on an earlier
// day as one batch once the day's release time has passed, in sorted
// canonical order. Only the set of hints crosses: not their order, not
// when they were emitted. The day only moves forward: a clock stepped
// back keeps the latest day seen, so it cannot reopen an earlier day's
// dedupe or release.
type Emitter struct {
	cfg Config

	mu          sync.Mutex
	seq         int
	day         string          // latest UTC day seen; never moves back
	seen        map[string]bool // canonical forms queued or asked today
	backlog     []queued        // waiting to cross, oldest first
	pending     map[int]Pending // asks waiting for the owner
	lastRelease string          // day of the last successful batch
}

// New builds an Emitter and rebuilds the latest day, today's dedupe, the
// waiting batch, and the open asks from the log, so a restart neither
// reopens a day nor loses a hint or a question to the owner.
func New(cfg Config) (*Emitter, error) {
	if cfg.Schema == nil {
		cfg.Schema = Default()
	}
	if cfg.Log == nil || cfg.Outbox == nil {
		return nil, errors.New("hint: Log and Outbox are required")
	}
	for c, m := range cfg.Policy {
		if !cfg.Schema.hasCategory(c) {
			return nil, fmt.Errorf("hint: policy names unknown category %q", c)
		}
		if m != Automatic && m != Ask && m != Never {
			return nil, fmt.Errorf("hint: policy for %s: unknown mode %d", c, m)
		}
	}
	if cfg.DailyLimit <= 0 {
		cfg.DailyLimit = DefaultDailyLimit
	}
	if cfg.EmbargoReserve <= 0 {
		cfg.EmbargoReserve = (cfg.DailyLimit + 3) / 4
	}
	if cfg.EmbargoReserve >= cfg.DailyLimit {
		return nil, errors.New("hint: EmbargoReserve must leave room under DailyLimit")
	}
	if cfg.MaxBacklog <= 0 {
		cfg.MaxBacklog = 7 * cfg.DailyLimit
	}
	if cfg.ReleaseAt <= 0 {
		cfg.ReleaseAt = DefaultReleaseAt
	}
	if cfg.ReleaseAt >= 24*time.Hour {
		return nil, errors.New("hint: ReleaseAt must be within a day")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	e := &Emitter{cfg: cfg, pending: map[int]Pending{}}
	rs, err := cfg.Log.List()
	if err != nil {
		return nil, err
	}
	failed := map[int]bool{} // Forwarded records whose send failed
	for _, r := range rs {
		if r.Outcome == SendFailed {
			failed[r.Ref] = true
		}
		if r.Day > e.day {
			e.day = r.Day
		}
		if r.Seq > e.seq {
			e.seq = r.Seq
		}
	}
	e.roll()
	crossed := map[int]bool{} // Queued or Approved records that crossed
	for _, r := range rs {
		if r.Outcome == Forwarded && !failed[r.Seq] {
			crossed[r.Ref] = true
			if r.Day > e.lastRelease {
				e.lastRelease = r.Day
			}
		}
	}
	for _, r := range rs {
		h := Hint{Kind: r.Kind, Fields: r.Fields}
		switch r.Outcome {
		case Asked:
			e.pending[r.Seq] = Pending{ID: r.Seq, Day: r.Day, Kind: r.Kind, Fields: r.Fields}
		case Approved, Declined, OverLimit:
			delete(e.pending, r.Ref) // an OverLimit with no Ref settles nothing
		}
		if r.Outcome != Queued && r.Outcome != Approved && r.Outcome != Asked {
			continue
		}
		k, err := cfg.Schema.check(h)
		if err != nil {
			continue // the schema changed; it can no longer cross
		}
		c, _ := cfg.Schema.Canonical(h)
		if r.Day == e.day {
			e.seen[string(c)] = true
		}
		if r.Outcome != Asked && !crossed[r.Seq] {
			e.backlog = append(e.backlog, queued{seq: r.Seq, day: r.Day, embargo: k.Embargo, canon: string(c)})
		}
	}
	return e, nil
}

// roll moves the day forward to the clock's UTC day if that is later, and
// resets the day's dedupe when it moves. Callers hold mu (or own e).
func (e *Emitter) roll() {
	d := e.cfg.Now().UTC().Format("2006-01-02")
	if d > e.day {
		e.day = d
		e.seen = nil
	}
	if e.seen == nil {
		e.seen = map[string]bool{}
	}
}

func (e *Emitter) record(r Record) error {
	e.seq++
	r.Seq, r.Day = e.seq, e.day
	return e.cfg.Log.Append(r)
}

// waiting reports whether an identical hint is already queued or asked.
func (e *Emitter) waiting(canon string) bool {
	if e.seen[canon] {
		return true
	}
	for _, q := range e.backlog {
		if q.canon == canon {
			return true
		}
	}
	for _, p := range e.pending {
		if c, err := e.cfg.Schema.Canonical(Hint{Kind: p.Kind, Fields: p.Fields}); err == nil && string(c) == canon {
			return true
		}
	}
	return false
}

func (e *Emitter) backlogFull(embargo bool) bool {
	n := 0
	for _, q := range e.backlog {
		if q.embargo == embargo {
			n++
		}
	}
	return n >= e.cfg.MaxBacklog
}

// Emit validates h, logs it, and queues, asks, or withholds it by the
// owner's policy for its category. A hint that fails the schema is logged
// as Refused with no content and returns ErrInvalid. A repeat of a hint
// queued or asked today, or still waiting, is a Duplicate. A log failure
// stops the hint.
func (e *Emitter) Emit(h Hint) (Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roll()
	k, err := e.cfg.Schema.check(h)
	if err != nil {
		if lerr := e.record(Record{Outcome: Refused}); lerr != nil {
			return Result{}, lerr
		}
		return Result{Outcome: Refused}, err
	}
	canon, _ := e.cfg.Schema.Canonical(h)
	rec := Record{Category: k.Category, Kind: h.Kind, Fields: copyFields(h.Fields)}
	out := func(o Outcome) (Result, error) {
		rec.Outcome = o
		return Result{Outcome: o}, e.record(rec)
	}
	mode := e.cfg.Policy[k.Category]
	switch {
	case mode == Never:
		return out(Withheld)
	case e.waiting(string(canon)):
		return out(Duplicate)
	case mode == Ask:
		res, err := out(Asked)
		if err != nil {
			return res, err
		}
		e.seen[string(canon)] = true
		res.ID = e.seq
		e.pending[e.seq] = Pending{ID: e.seq, Day: e.day, Kind: rec.Kind, Fields: copyFields(rec.Fields)}
		return res, nil
	case e.backlogFull(k.Embargo):
		return out(OverLimit)
	}
	res, err := out(Queued)
	if err != nil {
		return res, err
	}
	e.seen[string(canon)] = true
	e.backlog = append(e.backlog, queued{seq: e.seq, day: e.day, embargo: k.Embargo, canon: string(canon)})
	return res, nil
}

// Release sends the hints queued on days before today as one sorted batch,
// at most DailyLimit of them, once today's release time has passed and no
// batch has gone today. Embargo kinds get EmbargoReserve slots first,
// routine kinds the rest; either class takes slots the other leaves
// unused; within a class the oldest go first and the rest wait. Each
// hint's Forwarded record is written before the send; if the send fails,
// that is logged, the hints stay queued, and a later call retries.
func (e *Emitter) Release() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roll()
	now := e.cfg.Now().UTC()
	// A clock behind the latest day waits until it catches up, so a batch
	// still goes only at the release time.
	if e.lastRelease >= e.day || now.Format("2006-01-02") != e.day || now.Sub(now.Truncate(24*time.Hour)) < e.cfg.ReleaseAt {
		return nil
	}
	var emb, rout []queued
	for _, q := range e.backlog {
		if q.day >= e.day {
			continue
		}
		if q.embargo {
			emb = append(emb, q)
		} else {
			rout = append(rout, q)
		}
	}
	nEmb := min(len(emb), e.cfg.EmbargoReserve)
	nRout := min(len(rout), e.cfg.DailyLimit-nEmb)
	nEmb = min(len(emb), e.cfg.DailyLimit-nRout)
	batch := append(append([]queued(nil), emb[:nEmb]...), rout[:nRout]...)
	if len(batch) == 0 {
		return nil
	}
	sort.Slice(batch, func(i, j int) bool { return batch[i].canon < batch[j].canon })
	var fwd []int
	for _, q := range batch {
		if err := e.record(Record{Outcome: Forwarded, Ref: q.seq}); err != nil {
			return e.failed(fwd, err)
		}
		fwd = append(fwd, e.seq)
	}
	out := make([][]byte, len(batch))
	for i, q := range batch {
		out[i] = []byte(q.canon)
	}
	if err := e.cfg.Outbox.Send(out); err != nil {
		return e.failed(fwd, fmt.Errorf("hint: outbox: %w", err))
	}
	sent := map[int]bool{}
	for _, q := range batch {
		sent[q.seq] = true
	}
	kept := e.backlog[:0]
	for _, q := range e.backlog {
		if !sent[q.seq] {
			kept = append(kept, q)
		}
	}
	e.backlog = kept
	e.lastRelease = e.day
	return nil
}

// failed logs a SendFailed record for each Forwarded record written for a
// batch that did not go, and returns err.
func (e *Emitter) failed(fwd []int, err error) error {
	for _, s := range fwd {
		if lerr := e.record(Record{Outcome: SendFailed, Ref: s}); lerr != nil {
			return errors.Join(err, lerr)
		}
	}
	return err
}

// Pending lists the hints waiting for the owner, oldest first.
func (e *Emitter) Pending() []Pending {
	e.mu.Lock()
	defer e.mu.Unlock()
	ps := make([]Pending, 0, len(e.pending))
	for _, p := range e.pending {
		ps = append(ps, p)
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].ID < ps[j].ID })
	return ps
}

// Approve queues an asked hint for the next batch. It must be called only
// from an owner action (the local page or an owner-channel command), never
// from a machine.
func (e *Emitter) Approve(id int) error { return e.settle(id, true) }

// Decline drops an asked hint; it never crosses.
func (e *Emitter) Decline(id int) error { return e.settle(id, false) }

func (e *Emitter) settle(id int, approve bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roll()
	p, ok := e.pending[id]
	if !ok {
		return ErrNoPending
	}
	rec := Record{Kind: p.Kind, Fields: copyFields(p.Fields), Ref: id, Outcome: Declined}
	h := Hint{Kind: p.Kind, Fields: p.Fields}
	k, err := e.cfg.Schema.check(h)
	if err != nil {
		// The schema changed since the ask; the old hint no longer
		// validates, so it cannot cross.
		delete(e.pending, id)
		return e.record(rec)
	}
	rec.Category = k.Category
	if approve && e.backlogFull(k.Embargo) {
		rec.Outcome = OverLimit
	} else if approve {
		rec.Outcome = Approved
	}
	if err := e.record(rec); err != nil {
		return err
	}
	delete(e.pending, id)
	if rec.Outcome == Approved {
		canon, _ := e.cfg.Schema.Canonical(h)
		e.seen[string(canon)] = true
		e.backlog = append(e.backlog, queued{seq: e.seq, day: e.day, embargo: k.Embargo, canon: string(canon)})
	}
	return nil
}

func copyFields(f map[string]string) map[string]string {
	c := make(map[string]string, len(f))
	for k, v := range f {
		c[k] = v
	}
	return c
}
