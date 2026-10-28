package policy

import (
	"bytes"
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
	ErrPending       = errors.New("policy: another loosening is waiting; cancel it or let it apply first")
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
	After uint64 `json:"after"` // the last step before it was signed
}

// Step is one tightening applied on top of the base version: from the
// channel with no assertion, or signed by the owner (an asserted
// tightening, or any tightening the owner signed on the page). A signed
// step keeps its version and Prev, the document it tightened, so a restart
// can check that the owner signed exactly Op.
type Step struct {
	Seq    uint64  `json:"seq"`
	Op     Op      `json:"op"`
	Signed *Signed `json:"signed,omitempty"`
	Prev   []byte  `json:"prev,omitempty"` // canonical
}

type state struct {
	Base    *Signed   `json:"base"`
	Steps   []Step    `json:"steps"`
	Pending []Pending `json:"pending"` // at most one
	Seq     uint64    `json:"seq"`
	// Spent is the highest version ever accepted, applied, pending or
	// cancelled. It only rises, so a cancelled loosening's assertion
	// cannot be proposed again.
	Spent uint64 `json:"spent"`
}

// Outcome is what Propose did.
type Outcome struct {
	Class   Class
	Applied bool   // a tightening, applied at once
	Pending string // a loosening: its ID, applying at DueMS unless cancelled
	DueMS   int64
}

// Engine holds the policy in force: the base version (the last signed
// loosening applied), the tightenings applied since, and the loosening
// waiting, if any. It is not safe for concurrent use; the daemon
// serialises calls.
type Engine struct {
	owner key.PublicKey
	store Store
	st    state
	cur   Document
	used  map[string][]int64 // device → recent tightening times, for the limit
}

// Open loads the engine's state from store and re-verifies it: the base
// version against owner, each step as a closed-list tightening (an
// asserted one only with the owner's signature over it), and the pending
// loosening's signature. Empty, it is version 0: default deny, nothing
// allowed.
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
		next, err := e.replay(e.cur, s)
		if err != nil || s.Seq > e.st.Seq {
			return nil, fmt.Errorf("%w: step %d: %v", ErrCorrupt, s.Seq, err)
		}
		e.cur = next
	}
	if e.cur.Version > e.st.Spent || len(e.st.Pending) > 1 {
		return nil, fmt.Errorf("%w: version %d, spent %d", ErrCorrupt, e.cur.Version, e.st.Spent)
	}
	for _, p := range e.st.Pending {
		d, err := e.check(p.Signed)
		if err != nil || p.ID != p.Key.Root.Serial || d.Version > e.st.Spent || p.After > e.st.Seq {
			return nil, fmt.Errorf("%w: pending %s", ErrCorrupt, p.ID)
		}
	}
	return e, nil
}

// replay applies a stored step to d. An unsigned step must be a closed-list
// tightening that needs no owner; a signed one must carry the owner's
// signature over a document that is exactly Prev with Op applied.
func (e *Engine) replay(d Document, s Step) (Document, error) {
	next, ok := Apply(d, s.Op)
	if !ok {
		return d, ErrNotTightening
	}
	c := Classify(d, next)
	if !c.Tightening {
		return d, ErrNotTightening
	}
	if s.Signed == nil {
		if c.Owner || s.Prev != nil {
			return d, ErrNeedsOwner
		}
		return next, nil
	}
	sd, err := e.check(*s.Signed)
	if err != nil {
		return d, err
	}
	prev, err := Decode(s.Prev)
	if err != nil {
		return d, err
	}
	if sc := Classify(prev, sd); !sc.Tightening || sc.Op != s.Op {
		return d, ErrUnbound
	}
	next.Version = max(next.Version, sd.Version)
	return next, nil
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

// Current is the policy in force. Its Version is the highest signed
// version applied.
func (e *Engine) Current() Document { return e.cur.normal() }

// Pending is the loosening waiting, if any.
func (e *Engine) Pending() []Pending { return slices.Clone(e.st.Pending) }

// Propose takes an owner-signed version. sig is the owner's assertion over
// next's root (Verify), and next's version must be above every version
// ever accepted, cancelled ones included. A closed-list tightening, an
// asserted one included, applies at once as a signed step, and a loosening
// waiting meanwhile is kept: the step is applied again on top of it when
// it lands. Anything else is a loosening: it waits Wait from now, the time
// the assertion was checked, and is refused while another loosening waits
// (ErrPending), since it was drawn against the policy without that one and
// applying both would silently undo the first. Restoring an older document
// is a new, higher version like any other, classified by what it changes
// (NET-2 Recovery).
func (e *Engine) Propose(next Proposal, sig []byte, nowMS int64) (Outcome, error) {
	k, err := Verify(e.owner, e.st.Spent, next, sig)
	if err != nil {
		return Outcome{}, err
	}
	doc, err := Encode(next.Doc)
	if err != nil {
		return Outcome{}, err
	}
	s := Signed{Key: k, Doc: doc, Diff: slices.Clone(next.Diff)}
	c := Classify(e.cur, next.Doc)
	if !c.Tightening && len(e.st.Pending) > 0 {
		return Outcome{}, ErrPending
	}
	st := e.st
	st.Spent = next.Doc.Version // above the floor, so it rises
	if c.Tightening {
		prev, err := Encode(e.cur)
		if err != nil {
			return Outcome{}, err
		}
		st.Seq++
		st.Steps = append(slices.Clone(st.Steps), Step{Seq: st.Seq, Op: c.Op, Signed: &s, Prev: prev})
		if err := e.save(st); err != nil {
			return Outcome{}, err
		}
		e.cur = next.Doc.normal()
		return Outcome{Class: c, Applied: true}, nil
	}
	p := Pending{Signed: s, ID: k.Root.Serial, DueMS: nowMS + Wait, After: st.Seq}
	st.Pending = []Pending{p}
	if err := e.save(st); err != nil {
		return Outcome{}, err
	}
	return Outcome{Class: c, Pending: p.ID, DueMS: p.DueMS}, nil
}

// Cancel drops a pending loosening (NET-4: the owner can cancel it within
// the wait). The page calls it after the owner's passkey. Its version stays
// spent.
func (e *Engine) Cancel(id string) error {
	i := slices.IndexFunc(e.st.Pending, func(p Pending) bool { return p.ID == id })
	if i < 0 {
		return ErrNoPending
	}
	st := e.st
	st.Pending = slices.Delete(slices.Clone(st.Pending), i, i+1)
	return e.save(st)
}

// Tick applies the pending loosening if it is due at now, and returns its
// ID. It becomes the new base, and every step applied since it was signed,
// unsigned or signed, is applied again on top of it, so no tightening is
// undone and no signed loosening is dropped. A step that no longer applies
// (the loosening removed its target) is dropped with it.
func (e *Engine) Tick(nowMS int64) ([]string, error) {
	if len(e.st.Pending) == 0 || e.st.Pending[0].DueMS > nowMS {
		return nil, nil
	}
	p := e.st.Pending[0]
	d, err := Decode(p.Doc)
	if err != nil {
		return nil, err
	}
	st := e.st
	st.Pending = nil
	var kept []Step
	for _, s := range st.Steps {
		if s.Seq <= p.After {
			continue
		}
		if next, err := e.replay(d, s); err == nil {
			d = next
			kept = append(kept, s)
		}
	}
	base := p.Signed
	st.Base, st.Steps = &base, kept
	if err := e.save(st); err != nil {
		return nil, err
	}
	e.cur = d
	return []string{p.ID}, nil
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

// Export is the policy for the core's backup (NET-2 Recovery, BAK-1),
// served as a channel read by slice d: the signed versions in force, with
// their documents and assertions, and the policy in force to restore from.
// It holds no secret: a document carries no Wi-Fi password or device
// secret, only identities (decision 8, decision 10).
type Export struct {
	Base    *Signed  `json:"base"`
	Signed  []Signed `json:"signed"` // the signed steps since Base
	Current []byte   `json:"current"`
}

// Export is the engine's Export, encoded.
func (e *Engine) Export() ([]byte, error) {
	cur, err := Encode(e.cur)
	if err != nil {
		return nil, err
	}
	x := Export{Base: e.st.Base, Signed: []Signed{}, Current: cur}
	for _, s := range e.st.Steps {
		if s.Signed != nil {
			x.Signed = append(x.Signed, *s.Signed)
		}
	}
	return json.Marshal(x)
}

// ReadExport checks an export's signatures against owner and returns the
// policy to restore. The export comes back from the core, so it restores
// only through Propose: the owner signs the returned document as a new,
// higher version, on the page, and it applies like any other.
func ReadExport(owner key.PublicKey, b []byte) (Document, error) {
	var x Export
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&x); err != nil || dec.More() {
		return Document{}, ErrMalformed
	}
	e := &Engine{owner: owner}
	for _, s := range append(slices.Clone(x.Signed), derefs(x.Base)...) {
		if _, err := e.check(s); err != nil {
			return Document{}, err
		}
	}
	return Decode(x.Current)
}

func derefs(s *Signed) []Signed {
	if s == nil {
		return nil
	}
	return []Signed{*s}
}
