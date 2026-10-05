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

// DefaultDailyLimit is how many hints may cross or be asked per UTC day
// when Config.DailyLimit is zero.
const DefaultDailyLimit = 20

// ErrNoPending is returned when an ID names no hint waiting for the owner.
var ErrNoPending = errors.New("hint: no such pending hint")

// Outbox receives canonical hints for the clean-room builder.
type Outbox interface {
	Send(canonical []byte) error
}

// Config sets up an Emitter.
type Config struct {
	Schema     *Schema         // nil means Default()
	Policy     map[string]Mode // by category; absent means Automatic
	DailyLimit int             // 0 means DefaultDailyLimit
	Log        Log             // required
	Outbox     Outbox          // required
	Now        func() time.Time
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

// Emitter is the private side's single exit to the bridge.
type Emitter struct {
	cfg Config

	mu      sync.Mutex
	seq     int
	day     string
	count   int             // crossed or asked today
	seen    map[string]bool // canonical forms crossed or asked today
	pending map[int]Pending
}

// New builds an Emitter and rebuilds today's counts and the pending asks
// from the log, so a restart neither resets the daily bound nor loses an
// open question to the owner.
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
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	e := &Emitter{cfg: cfg, pending: map[int]Pending{}}
	rs, err := cfg.Log.List()
	if err != nil {
		return nil, err
	}
	e.roll()
	failed := map[int]bool{} // records whose send failed
	for _, r := range rs {
		if r.Outcome == SendFailed {
			failed[r.Ref] = true
		}
	}
	for _, r := range rs {
		if r.Seq > e.seq {
			e.seq = r.Seq
		}
		switch r.Outcome {
		case Asked:
			e.pending[r.Seq] = Pending{ID: r.Seq, Day: r.Day, Kind: r.Kind, Fields: r.Fields}
		case Approved, Declined:
			if !failed[r.Seq] {
				delete(e.pending, r.Ref)
			}
		}
		counts := r.Outcome == Asked || (r.Outcome == Forwarded && !failed[r.Seq])
		if r.Day == e.day && counts {
			e.count++
			if c, err := cfg.Schema.Canonical(Hint{Kind: r.Kind, Fields: r.Fields}); err == nil {
				e.seen[string(c)] = true
			}
		}
	}
	return e, nil
}

// roll resets the daily state when the UTC day changes. Callers hold mu
// (or own e exclusively).
func (e *Emitter) roll() {
	d := e.cfg.Now().UTC().Format("2006-01-02")
	if d != e.day {
		e.day, e.count, e.seen = d, 0, map[string]bool{}
	}
}

func (e *Emitter) record(r Record) error {
	e.seq++
	r.Seq, r.Day = e.seq, e.day
	return e.cfg.Log.Append(r)
}

// Emit validates h, logs it, and forwards, asks, or withholds it by the
// owner's policy for its category. A hint that fails the schema is logged
// as Refused with no content and returns ErrInvalid. A log failure stops
// the hint: nothing crosses unlogged.
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
	case e.seen[string(canon)]:
		return out(Duplicate)
	case e.count >= e.cfg.DailyLimit:
		return out(OverLimit)
	case mode == Ask:
		res, err := out(Asked)
		if err != nil {
			return res, err
		}
		e.count++
		e.seen[string(canon)] = true
		res.ID = e.seq
		e.pending[e.seq] = Pending{ID: e.seq, Day: e.day, Kind: rec.Kind, Fields: copyFields(rec.Fields)}
		return res, nil
	}
	// Logged before it is sent, so nothing crosses unlogged; a failed send
	// is then logged against that record and does not count.
	if res, err := out(Forwarded); err != nil {
		return res, err
	}
	fwd := e.seq
	if err := e.cfg.Outbox.Send(canon); err != nil {
		if lerr := e.record(Record{Outcome: SendFailed, Ref: fwd}); lerr != nil {
			return Result{Outcome: SendFailed}, lerr
		}
		return Result{Outcome: SendFailed}, fmt.Errorf("hint: outbox: %w", err)
	}
	e.count++
	e.seen[string(canon)] = true
	return Result{Outcome: Forwarded}, nil
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

// Approve forwards an asked hint. It is called only from an owner action
// (the local page or an owner-channel command), never from a machine.
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
	if !approve {
		delete(e.pending, id)
		return e.record(rec)
	}
	// As in Emit: logged first; a failed send is logged against the
	// approval and the hint stays pending, so the owner can approve again.
	rec.Outcome = Approved
	if err := e.record(rec); err != nil {
		return err
	}
	ap := e.seq
	canon, _ := e.cfg.Schema.Canonical(h)
	if err := e.cfg.Outbox.Send(canon); err != nil {
		if lerr := e.record(Record{Outcome: SendFailed, Ref: ap}); lerr != nil {
			return lerr
		}
		return fmt.Errorf("hint: outbox: %w", err)
	}
	delete(e.pending, id)
	return nil
}

func copyFields(f map[string]string) map[string]string {
	c := make(map[string]string, len(f))
	for k, v := range f {
		c[k] = v
	}
	return c
}
