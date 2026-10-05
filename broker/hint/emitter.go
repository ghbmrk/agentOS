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
	// Config.DailyLimit is zero (arbitrator's ruling on #40).
	DefaultDailyLimit = 5
	// DefaultEmbargoReserve is the batch slots kept for embargo kinds when
	// Config.EmbargoReserve is zero, capped to leave one routine slot.
	DefaultEmbargoReserve = 2
	// DefaultDedupeDays is how many days a hint counts as a duplicate of
	// an identical one queued or asked, when Config.DedupeDays is zero.
	DefaultDedupeDays = 7
	// DefaultReleaseAt is the UTC time of day a batch is released when
	// Config.ReleaseAt is zero.
	DefaultReleaseAt = 4 * time.Hour
)

// ErrNoPending is returned when an ID names no hint waiting for the owner.
var ErrNoPending = errors.New("hint: no such pending hint")

// Outbox receives each day's batch of canonical hints for the clean-room
// builder, sorted, with the day the batch belongs to. Each day labels at
// most one batch, so Send must be idempotent by day: after a crash, or an
// error that came after delivery, the emitter sends the same batch (the
// bytes recorded when it was formed) for the same day again, and the
// outbox delivers a day at most once.
type Outbox interface {
	Send(day string, batch [][]byte) error
}

// Config sets up an Emitter.
type Config struct {
	Schema *Schema         // nil means Default()
	Policy map[string]Mode // by category; absent means Automatic

	// DailyLimit caps one batch (0 means DefaultDailyLimit). EmbargoReserve
	// of its slots are kept for embargo kinds such as vuln (0 means
	// DefaultEmbargoReserve, at most DailyLimit-1); slots one class leaves
	// unused go to the other. Hints over the cap wait for the next batch.
	DailyLimit     int
	EmbargoReserve int
	// DedupeDays: a hint identical to one queued or asked within this many
	// days (today included) is a Duplicate (0 means DefaultDedupeDays).
	DedupeDays int
	// MaxBacklog bounds the hints of each class waiting to cross (0 means
	// 7 × DailyLimit). Over it, a hint is logged OverLimit and dropped.
	// MaxPending bounds the asks waiting for the owner the same way.
	// Asks unanswered for DedupeDays expire as Expired (declined).
	MaxBacklog int
	MaxPending int
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

// batch is a Forwarded record whose send has not been committed by a Sent
// record.
type batch struct {
	seq    int // the Forwarded record
	day    string
	items  []queued
	failed bool // a SendFailed record is already logged for it
}

// Emitter is the private side's single exit to the bridge.
//
// Emit never sends. It queues a hint (or asks the owner about it), and
// Release, called on any schedule, sends every hint queued on an earlier
// day as one batch once the day's release time has passed, in sorted
// canonical order. Only the set of hints crosses: not their order, not
// when they were emitted. The day only moves forward: a clock stepped
// back keeps the latest day seen, so it cannot shorten the dedupe window
// or reopen an earlier day's release. The host clock is trusted: each step
// forward to a new day allows one more batch.
//
// A batch is one Forwarded record, written before the send, and a Sent
// record after the outbox accepts it. A batch without Sent (a failed send,
// or a crash in between) is resent, exactly the same set for the same
// day, before any new batch.
type Emitter struct {
	cfg Config

	mu          sync.Mutex
	seq         int
	day         string            // latest UTC day seen; never moves back
	seen        map[string]string // canonical form -> latest day queued or asked
	backlog     []queued          // waiting to cross, oldest first
	pending     map[int]Pending   // asks waiting for the owner
	inflight    *batch            // forwarded, not yet committed Sent
	lastRelease string            // day of the latest batch formed
}

// New builds an Emitter and rebuilds the latest day, the dedupe window, the
// waiting hints, any batch forwarded but not committed Sent, and the open
// asks from the log, so a restart neither reopens a day nor loses a hint,
// a batch, or a question to the owner.
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
		cfg.EmbargoReserve = min(DefaultEmbargoReserve, cfg.DailyLimit-1)
	}
	if cfg.DedupeDays <= 0 {
		cfg.DedupeDays = DefaultDedupeDays
	}
	if cfg.EmbargoReserve >= cfg.DailyLimit {
		return nil, errors.New("hint: EmbargoReserve must leave room under DailyLimit")
	}
	if cfg.MaxBacklog <= 0 {
		cfg.MaxBacklog = 7 * cfg.DailyLimit
	}
	if cfg.MaxPending <= 0 {
		cfg.MaxPending = 7 * cfg.DailyLimit
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
	sent := map[int]bool{} // Forwarded records committed by a Sent record
	for _, r := range rs {
		if r.Outcome == Sent {
			sent[r.Ref] = true
		}
		if r.Day > e.day {
			e.day = r.Day
		}
		if r.Seq > e.seq {
			e.seq = r.Seq
		}
	}
	e.roll()
	inBatch := map[int]bool{} // Queued or Approved records in any batch
	var open *Record          // the latest Forwarded record not committed
	for i, r := range rs {
		if r.Outcome != Forwarded {
			continue
		}
		for _, ref := range r.Refs {
			inBatch[ref] = true
		}
		if r.Day > e.lastRelease {
			e.lastRelease = r.Day
		}
		if !sent[r.Seq] {
			open = &rs[i]
		}
	}
	items := map[int]queued{}
	for _, r := range rs {
		h := Hint{Kind: r.Kind, Fields: r.Fields}
		switch r.Outcome {
		case Asked:
			e.pending[r.Seq] = Pending{ID: r.Seq, Day: r.Day, Kind: r.Kind, Fields: r.Fields}
		case Approved, Declined, Expired, OverLimit:
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
		if r.Day > e.seen[string(c)] {
			e.seen[string(c)] = r.Day
		}
		if r.Outcome == Asked {
			continue
		}
		q := queued{seq: r.Seq, day: r.Day, embargo: k.Embargo, canon: string(c)}
		items[r.Seq] = q
		if !inBatch[r.Seq] {
			e.backlog = append(e.backlog, q)
		}
	}
	if open != nil {
		// Resend the bytes recorded at Forward time, not a rebuild under
		// the current schema, so the set cannot change (H12).
		b := &batch{seq: open.Seq, day: open.Day}
		if len(open.Batch) == 0 {
			// A record from before Batch existed: rebuild from Refs, so
			// its hints are not committed Sent as an empty set.
			for _, ref := range open.Refs {
				if q, ok := items[ref]; ok {
					b.items = append(b.items, q)
				}
			}
		}
		for i, c := range open.Batch {
			q := queued{canon: c}
			if i < len(open.Refs) {
				q.seq = open.Refs[i]
			}
			if it, ok := items[q.seq]; ok {
				q.day, q.embargo = it.day, it.embargo
			}
			b.items = append(b.items, q)
		}
		for _, r := range rs {
			if r.Outcome == SendFailed && r.Ref == open.Seq {
				b.failed = true
			}
		}
		e.inflight = b
	}
	return e, nil
}

// roll moves the day forward to the clock's UTC day if that is later.
// Callers hold mu (or own e).
func (e *Emitter) roll() {
	if d := e.cfg.Now().UTC().Format("2006-01-02"); d > e.day {
		e.day = d
	}
	if e.seen == nil {
		e.seen = map[string]string{}
	}
}

// recent reports whether day is within the dedupe window ending today.
func (e *Emitter) recent(day string) bool {
	d, err1 := time.Parse("2006-01-02", day)
	t, err2 := time.Parse("2006-01-02", e.day)
	if err1 != nil || err2 != nil {
		return true // unreadable: fail toward duplicate
	}
	return t.Sub(d) < time.Duration(e.cfg.DedupeDays)*24*time.Hour
}

func (e *Emitter) record(r Record) error {
	e.seq++
	r.Seq, r.Day = e.seq, e.day
	return e.cfg.Log.Append(r)
}

// waiting reports whether an identical hint is waiting, or was queued or
// asked within the dedupe window.
func (e *Emitter) waiting(canon string) bool {
	if d, ok := e.seen[canon]; ok && e.recent(d) {
		return true
	}
	for _, q := range e.backlog {
		if q.canon == canon {
			return true
		}
	}
	if e.inflight != nil {
		for _, q := range e.inflight.items {
			if q.canon == canon {
				return true
			}
		}
	}
	for _, p := range e.pending {
		if c, err := e.cfg.Schema.Canonical(Hint{Kind: p.Kind, Fields: p.Fields}); err == nil && string(c) == canon {
			return true
		}
	}
	return false
}

// expire settles asks unanswered for DedupeDays as Expired (UX 3: an
// unanswered ask counts as declined).
func (e *Emitter) expire() error {
	ids := make([]int, 0, len(e.pending))
	for id, p := range e.pending {
		if !e.recent(p.Day) {
			ids = append(ids, id)
		}
	}
	sort.Ints(ids)
	for _, id := range ids {
		p := e.pending[id]
		if err := e.record(Record{Outcome: Expired, Ref: id, Kind: p.Kind, Fields: copyFields(p.Fields)}); err != nil {
			return err
		}
		delete(e.pending, id)
	}
	return nil
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
// queued or asked within DedupeDays, or still waiting, is a Duplicate. A
// log failure stops the hint.
func (e *Emitter) Emit(h Hint) (Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roll()
	if err := e.expire(); err != nil {
		return Result{}, err
	}
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
	case mode == Ask && len(e.pending) >= e.cfg.MaxPending:
		return out(OverLimit)
	case mode == Ask:
		res, err := out(Asked)
		if err != nil {
			return res, err
		}
		e.seen[string(canon)] = e.day
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
	e.seen[string(canon)] = e.day
	e.backlog = append(e.backlog, queued{seq: e.seq, day: e.day, embargo: k.Embargo, canon: string(canon)})
	return res, nil
}

// Release sends the hints queued on days before today as one sorted batch,
// at most DailyLimit of them, once today's release time has passed and no
// batch has been formed today. Embargo kinds get EmbargoReserve slots
// first, routine kinds the rest; either class takes slots the other leaves
// unused; within a class the oldest go first and the rest wait. The batch's
// Forwarded record is written before the send and a Sent record after it.
// If a batch is still uncommitted (the send failed, or the box crashed
// before Sent was written), Release resends exactly that set, for its day,
// at the release time, and forms no new batch in the same call. Only a
// fixed broker timer may call Release (ASSUMPTIONS K3): the call time is
// the send time.
func (e *Emitter) Release() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roll()
	if err := e.expire(); err != nil {
		return err
	}
	now := e.cfg.Now().UTC()
	// A clock behind the latest day waits until it catches up, so a batch
	// still goes only at the release time.
	if now.Format("2006-01-02") != e.day || now.Sub(now.Truncate(24*time.Hour)) < e.cfg.ReleaseAt {
		return nil
	}
	if e.inflight != nil {
		return e.send()
	}
	if e.lastRelease >= e.day {
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
	items := append(append([]queued(nil), emb[:nEmb]...), rout[:nRout]...)
	if len(items) == 0 {
		return nil
	}
	sort.Slice(items, func(i, j int) bool { return items[i].canon < items[j].canon })
	refs := make([]int, len(items))
	canons := make([]string, len(items))
	for i, q := range items {
		refs[i], canons[i] = q.seq, q.canon
	}
	if err := e.record(Record{Outcome: Forwarded, Refs: refs, Batch: canons}); err != nil {
		return err
	}
	e.inflight = &batch{seq: e.seq, day: e.day, items: items}
	e.lastRelease = e.day
	in := map[int]bool{}
	for _, r := range refs {
		in[r] = true
	}
	kept := e.backlog[:0]
	for _, q := range e.backlog {
		if !in[q.seq] {
			kept = append(kept, q)
		}
	}
	e.backlog = kept
	return e.send()
}

// send offers the uncommitted batch to the outbox and commits it with a
// Sent record. A failure is logged once per batch; the batch stays for the
// next Release.
func (e *Emitter) send() error {
	b := e.inflight
	out := make([][]byte, len(b.items))
	for i, q := range b.items {
		out[i] = []byte(q.canon)
	}
	if err := e.cfg.Outbox.Send(b.day, out); err != nil {
		err = fmt.Errorf("hint: outbox: %w", err)
		if b.failed {
			return err
		}
		if lerr := e.record(Record{Outcome: SendFailed, Ref: b.seq}); lerr != nil {
			return errors.Join(err, lerr)
		}
		b.failed = true
		return err
	}
	if err := e.record(Record{Outcome: Sent, Ref: b.seq}); err != nil {
		return err // resent, idempotently, at the next Release
	}
	e.inflight = nil
	return nil
}

// Pending lists the hints waiting for the owner, oldest first, after
// expiring stale asks. If logging an expiry fails, stale asks are still
// left out.
func (e *Emitter) Pending() []Pending {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roll()
	_ = e.expire()
	ps := make([]Pending, 0, len(e.pending))
	for _, p := range e.pending {
		if e.recent(p.Day) {
			ps = append(ps, p)
		}
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
	if err := e.expire(); err != nil {
		return err
	}
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
		e.seen[string(canon)] = e.day
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
