package policy

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Wait is how long a loosening waits after the owner's assertion before it
// applies (NET-4 Loosening, Mark 2026-10-18 17:50Z).
const Wait int64 = 10 * 60 * 1000

// The per-device tightening limit: at most TightenLimit unsigned
// tightenings or secure-direction commands per device in any
// TightenWindow, so a compromised core that keeps relocking or cutting is
// capped (NET-4 Tightening). ASSUMPTIONS ENF-a-4.
const (
	TightenLimit  = 6
	TightenWindow = 60 * 60 * 1000
)

var (
	ErrNotTightening = errors.New("policy: not a closed-list tightening")
	ErrNeedsOwner    = errors.New("policy: a safety-list device's tightening needs the owner's passkey")
	ErrRateLimited   = errors.New("policy: tightening rate limit for this device")
	ErrNotSecure     = errors.New("policy: not the device's secure-direction command")
	ErrNoPending     = errors.New("policy: no such pending change")
	ErrCorrupt       = errors.New("policy: stored state does not verify")
)

// Store keeps the engine's state across restarts: the enforcer's sealed
// store in the daemon (slice l), a map in tests. Save replaces the whole
// state; Load returns nil when nothing was saved.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// Signed is one owner-signed version: its key and what the key commits to.
type Signed struct {
	Key  key.Key `json:"key"`
	Doc  []byte  `json:"doc"` // canonical
	Diff []byte  `json:"diff"`
}

// Pending is a signed loosening waiting out Wait.
type Pending struct {
	Signed
	ID    string `json:"id"` // the key's serial
	DueMS int64  `json:"due_ms"`
	After uint64 `json:"after"` // the last tightening step before it was signed
}

// Step is one unsigned tightening applied on top of the signed version.
type Step struct {
	Seq uint64 `json:"seq"`
	Op  Op     `json:"op"`
}

type state struct {
	Base    *Signed   `json:"base"`
	Steps   []Step    `json:"steps"`
	Pending []Pending `json:"pending"`
	Seq     uint64    `json:"seq"`
}

// Outcome is what Propose did.
type Outcome struct {
	Class   Class
	Applied bool   // a tightening, applied at once
	Pending string // a loosening: its ID, applying at DueMS unless cancelled
	DueMS   int64
}

// Engine holds the policy in force: the last owner-signed version, the
// closed-list tightenings applied since, and the loosenings waiting. It is
// not safe for concurrent use; the daemon serialises calls.
type Engine struct {
	owner key.PublicKey
	store Store
	st    state
	cur   Document
	used  map[string][]int64 // device → recent tightening times, for the limit
}

// Open loads the engine's state from store and re-verifies it: the signed
// version against owner, each tightening step as a closed-list op, and each
// pending loosening's signature. Empty, it is version 0: default deny,
// nothing allowed.
func Open(owner key.PublicKey, store Store) (*Engine, error) {
	e := &Engine{owner: owner, store: store, used: map[string][]int64{}}
	b, err := store.Load()
	if err != nil {
		return nil, err
	}
	if b == nil {
		return e, nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e.st); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if e.st.Base != nil {
		d, err := e.check(*e.st.Base)
		if err != nil {
			return nil, err
		}
		e.cur = d
	}
	for _, s := range e.st.Steps {
		next, ok := Apply(e.cur, s.Op)
		if !ok || !Classify(e.cur, next).Tightening || s.Seq > e.st.Seq {
			return nil, fmt.Errorf("%w: step %d", ErrCorrupt, s.Seq)
		}
		e.cur = next
	}
	for _, p := range e.st.Pending {
		if _, err := e.check(p.Signed); err != nil || p.ID != p.Key.Root.Serial {
			return nil, fmt.Errorf("%w: pending %s", ErrCorrupt, p.ID)
		}
	}
	return e, nil
}

// check verifies a stored version and returns its document.
func (e *Engine) check(s Signed) (Document, error) {
	d, err := Decode(s.Doc)
	if err != nil {
		return Document{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if err := Check(e.owner, s.Key, Proposal{d, s.Diff}); err != nil {
		return Document{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return d, nil
}

// Current is the policy in force.
func (e *Engine) Current() Document { return e.cur.normal() }

// Pending is the loosenings waiting, in the order they were signed.
func (e *Engine) Pending() []Pending { return slices.Clone(e.st.Pending) }

// floor is the highest version signed or pending: a new version must be
// above it.
func (e *Engine) floor() uint64 {
	v := e.cur.Version
	for _, p := range e.st.Pending {
		if d, err := Decode(p.Doc); err == nil && d.Version > v {
			v = d.Version
		}
	}
	return v
}

// Propose takes an owner-signed version. sig is the owner's assertion over
// next's root (Verify). A closed-list tightening applies at once; anything
// else is a loosening and waits Wait from now, the time the assertion was
// checked. Restoring an older document is a new, higher version like any
// other, classified by what it changes (NET-2 Recovery).
func (e *Engine) Propose(next Proposal, sig []byte, nowMS int64) (Outcome, error) {
	k, err := Verify(e.owner, e.floor(), next, sig)
	if err != nil {
		return Outcome{}, err
	}
	doc, err := Encode(next.Doc)
	if err != nil {
		return Outcome{}, err
	}
	s := Signed{Key: k, Doc: doc, Diff: slices.Clone(next.Diff)}
	c := Classify(e.cur, next.Doc)
	st := e.st
	if c.Tightening {
		st.Base, st.Steps = &s, nil
		if err := e.save(st); err != nil {
			return Outcome{}, err
		}
		e.cur = next.Doc.normal()
		return Outcome{Class: c, Applied: true}, nil
	}
	p := Pending{Signed: s, ID: k.Root.Serial, DueMS: nowMS + Wait, After: st.Seq}
	st.Pending = append(slices.Clone(st.Pending), p)
	if err := e.save(st); err != nil {
		return Outcome{}, err
	}
	return Outcome{Class: c, Pending: p.ID, DueMS: p.DueMS}, nil
}

// Cancel drops a pending loosening (NET-4: the owner can cancel it within
// the wait). The page calls it after the owner's passkey.
func (e *Engine) Cancel(id string) error {
	i := slices.IndexFunc(e.st.Pending, func(p Pending) bool { return p.ID == id })
	if i < 0 {
		return ErrNoPending
	}
	st := e.st
	st.Pending = slices.Delete(slices.Clone(st.Pending), i, i+1)
	return e.save(st)
}

// Tick applies every pending loosening due at now, in the order they fall
// due, and returns their IDs. The tightenings applied since a loosening was
// signed are applied again on top of it, so a later tightening is not
// undone. A pending version at or below the version in force was
// superseded by a later signed one and is dropped, not applied.
func (e *Engine) Tick(nowMS int64) ([]string, error) {
	st := e.st
	st.Pending = slices.Clone(st.Pending)
	slices.SortStableFunc(st.Pending, func(a, b Pending) int { return cmp.Compare(a.DueMS, b.DueMS) })
	cur := e.cur
	var applied []string
	for len(st.Pending) > 0 && st.Pending[0].DueMS <= nowMS {
		p := st.Pending[0]
		st.Pending = st.Pending[1:]
		d, err := Decode(p.Doc)
		if err != nil {
			return nil, err
		}
		if d.Version <= cur.Version {
			continue
		}
		var kept []Step
		for _, s := range st.Steps {
			if s.Seq <= p.After {
				continue
			}
			if next, ok := Apply(d, s.Op); ok {
				d = next
				kept = append(kept, s)
			}
		}
		base := p.Signed
		st.Base, st.Steps, cur = &base, kept, d
		applied = append(applied, p.ID)
	}
	if len(st.Pending) == len(e.st.Pending) {
		return nil, nil
	}
	if err := e.save(st); err != nil {
		return nil, err
	}
	e.cur = cur
	return applied, nil
}

// Tighten applies one closed-list tightening with no assertion: the path
// the enforcer channel and texts use (NET-4 Tightening). It goes through
// Classify, refuses a safety-list device's tightening (that needs the
// owner's passkey, Propose) and is rate-limited per device.
func (e *Engine) Tighten(op Op, nowMS int64) error {
	next, ok := Apply(e.cur, op)
	if !ok {
		return ErrNotTightening
	}
	c := Classify(e.cur, next)
	if !c.Tightening {
		return ErrNotTightening
	}
	if c.Owner {
		return ErrNeedsOwner
	}
	devs := opDevices(c.Op)
	if !e.allow(devs, nowMS) {
		return ErrRateLimited
	}
	st := e.st
	st.Seq++
	st.Steps = append(slices.Clone(st.Steps), Step{Seq: st.Seq, Op: c.Op})
	if err := e.save(st); err != nil {
		return err
	}
	e.spend(devs, nowMS)
	e.cur = next
	return nil
}

// Secure admits a safety-list device's named secure-direction command,
// such as a lock's lock or relock, which applies at once under the default
// standing key (NET-4 Tightening). It counts against the device's
// tightening limit.
func (e *Engine) Secure(device, cmd string, nowMS int64) error {
	if !e.cur.SecureCommand(device, cmd) {
		return ErrNotSecure
	}
	if !e.allow([]string{device}, nowMS) {
		return ErrRateLimited
	}
	e.spend([]string{device}, nowMS)
	return nil
}

func opDevices(op Op) []string {
	if op.Kind == RemovePair {
		return []string{op.Pair.A, op.Pair.B}
	}
	return []string{op.Device}
}

func (e *Engine) allow(devs []string, nowMS int64) bool {
	for _, d := range devs {
		e.used[d] = slices.DeleteFunc(e.used[d], func(t int64) bool { return t <= nowMS-TightenWindow })
		if len(e.used[d]) >= TightenLimit {
			return false
		}
	}
	return true
}

func (e *Engine) spend(devs []string, nowMS int64) {
	for _, d := range devs {
		e.used[d] = append(e.used[d], nowMS)
	}
}

// save writes st and, only if that succeeds, makes it the engine's state.
func (e *Engine) save(st state) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := e.store.Save(b); err != nil {
		return err
	}
	e.st = st
	return nil
}
