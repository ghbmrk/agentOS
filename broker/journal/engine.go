package journal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Engine runs intents through their lifecycle on top of a journal. All
// methods are safe for concurrent use. Executors and policies run without
// the engine lock held.
type Engine struct {
	mu     sync.Mutex
	store  Store
	policy Policy
	redact Redactor
	execs  map[string]Executor
	now    func() time.Time
	seq    uint64
	// intents holds every intent but the evicted denials; open holds the
	// ones not yet settled (succeeded or denied). STOP, STATUS and the
	// duplicate and fence checks read open, so their work does not grow
	// with history (CH-2). Records live only in the journal.
	intents map[string]*entry
	open    map[string]*entry
	// lingering holds the succeeded intents (not open) with an earlier
	// attempt still unknown or in flight, which STOP cancels too
	// (Security R22 on #1433), so that too reads no history.
	lingering map[string]*entry
	// byEffect indexes intents by effect fingerprint, so the same-effect
	// checks every dispatch makes (sameEffect, duplicateOf) read only the
	// intents with that effect, not every hot one (CH-2).
	byEffect map[string][]*entry
	// denied lists the denials in intents, oldest first. Past hotDenials
	// the oldest leave memory (they stay in the journal): cold keeps a
	// 16-byte key per evicted ID, so a resubmission is still recognised
	// (OP-1) and its status is read back from the journal. pinned holds
	// eviction off while replay or an erase needs every entry in place.
	denied  []string
	cold    map[coldKey]coldVal
	shapes  []coldShape // what evicted denials share, by coldVal.shape
	shapeIx map[coldShape]uint32
	pinned  bool
	stopped bool
	// stoppedAt holds every attempt that was in flight or unknown when a
	// STOP was recorded: the only attempts a cancel_requested record may
	// name. It is set by the stop record's apply, so replay rebuilds it,
	// and never cleared, so Stop's cancel stays legal after the attempt
	// settles or RESUME lifts STOP while the canceller runs.
	stoppedAt map[attemptRef]bool
	// fence maps an account to the intents left unresolved by the last
	// restart. Dispatch on the account waits until it is empty (OP-4).
	fence map[string]map[string]bool
	// missed counts the SettleUnknown rounds in a row that left a fenced
	// intent unresolved; Unconfirmed reads it (#1373).
	missed int
	// checks counts, per intent, the checks in a row that left its
	// unknown outcome unknown; at parkAfter the intent is parked (OP-2).
	// It is memory only: a restart starts the count again.
	checks map[string]int
	// redispatching holds the restart fence of an intent whose check
	// proved it was not done until its redispatch ends, so newer work on
	// the account cannot run ahead of it. Memory only.
	redispatching map[string]bool
	// newest is the latest record time in the journal, replayed or
	// committed. A clock behind it went back, as after an RTC loss at
	// the very restart reconcile handles, and is not trusted to say an
	// idempotency key is still remembered (OP-2).
	newest time.Time
	broken error
}

// hotDenials is how many settled denials stay in memory. Refusals are
// what an untrusted guest can produce without limit, so they are the
// history that is bounded (SIM-bound).
const hotDenials = 1024

// coldKey identifies an evicted denial: the first 16 bytes of the SHA-256
// of its ID. Two IDs colliding (odds 2^-128) read as one denial.
type coldKey [16]byte

// coldVal is what memory keeps of an evicted denial: enough to answer Get
// and an idempotent Submit without reading the journal, so a guest
// repeating old requests never holds the store while STOP waits on it.
// Params live only in the journal.
type coldVal struct {
	fp    [16]byte // prefix of the entry's fp
	shape uint32   // index in Engine.shapes
}

// coldShape is the rest of an evicted denial. Denials from one source
// share goal, origin, account, action, executor and refusal, so each
// distinct shape is kept once.
type coldShape struct {
	goal, origin, account, action, exec string
	reason, guest                       string
	phase                               Phase
}

func coldKeyOf(id string) coldKey {
	sum := sha256.Sum256([]byte(id))
	return coldKey(sum[:16])
}

type entry struct {
	seq        uint64 // of its RecSubmitted: submission order
	intent     Intent
	fp         string
	efp        string // effectFingerprint
	state      State
	permission Permission
	attempts   []Attempt
	quality    Quality
	authorized time.Time // when RecAuthorized was journaled
	dispatched time.Time // when the latest RecDispatched was journaled
	submitted  time.Time // when RecSubmitted was journaled
	erased     bool      // RecErased: params and evidence removed
	parkedSeq  uint64    // of the latest RecParked
	notDoneSeq uint64    // of the latest check that proved an attempt not done
	// firstDispatchSeq is the seq of its first RecDispatched, and
	// provedSeq that of the first record that proved one of its attempts
	// not applied, from any source (a check or the executor itself).
	// They say which same-effect intents are its rivals (rivals).
	// wentSeq is the seq of the first record that observed one of its
	// attempts succeeded: it holds back only rivals submitted before it
	// (blocks).
	firstDispatchSeq uint64
	provedSeq        uint64
	wentSeq          uint64
	// wentAt is when the attempt that wentSeq observed was last
	// dispatched: when the effect went (InUse, the gate's confirm-repeats
	// rule, D-116). knownAt is when that record was made: when the
	// success became known, which for an unknown outcome a check or the
	// owner settles may be days later (Security B11 on #1433).
	wentAt  time.Time
	knownAt time.Time
}

// attemptRef names one attempt of one intent.
type attemptRef struct {
	id string
	n  int
}

// Option configures Open.
type Option func(*Engine)

// WithClock sets the clock used to timestamp records.
func WithClock(now func() time.Time) Option { return func(e *Engine) { e.now = now } }

// Open replays the journal in store and returns an engine positioned after
// it. A torn final record is truncated; any other damage is ErrCorrupt.
// Attempts that were in flight become outcome_unknown, and their accounts
// are fenced until those intents are resolved (OP-4). redact is required:
// nothing reaches the journal without passing through it.
func Open(store Store, policy Policy, execs map[string]Executor, redact Redactor, opts ...Option) (*Engine, error) {
	if redact == nil {
		return nil, fmt.Errorf("%w: a redactor is required", ErrInvalid)
	}
	e := &Engine{
		store:   store,
		policy:  policy,
		redact:  redact,
		execs:   execs,
		now:     func() time.Time { return time.Now().UTC() },
		intents: map[string]*entry{},
		open:    map[string]*entry{},
		cold:    map[coldKey]coldVal{},
		shapeIx: map[coldShape]uint32{},
		fence:   map[string]map[string]bool{},
		checks:  map[string]int{},
		pinned:  true,

		byEffect:      map[string][]*entry{},
		lingering:     map[string]*entry{},
		redispatching: map[string]bool{},
	}
	for _, o := range opts {
		o(e)
	}
	data, err := store.ReadAll()
	if err != nil {
		return nil, err
	}
	recs, good, err := decodeJournal(data)
	if err != nil {
		return nil, err
	}
	if good < int64(len(data)) {
		if err := store.Truncate(good); err != nil {
			return nil, err
		}
	}
	for _, r := range recs {
		if err := e.validate(r); err != nil {
			return nil, fmt.Errorf("%w: record %d: %v", ErrCorrupt, r.Seq, err)
		}
		e.apply(r)
	}
	for _, en := range bySeq(e.open) {
		if en.state != InFlight {
			continue
		}
		n := en.attempts[len(en.attempts)-1].N
		if err := e.commit(Record{Type: RecObserved, ID: en.intent.ID, Attempt: n, Result: ResultUnknown,
			Source: "restart", Evidence: "in flight when the broker stopped"}); err != nil {
			return nil, err
		}
	}
	// An erase a crash cut off before its rewrite is finished now.
	if unerased(recs) {
		if err := e.rewriteErased(); err != nil {
			return nil, err
		}
	}
	for _, en := range bySeq(e.open) {
		if en.state == OutcomeUnknown && !en.parked() {
			if e.fence[en.intent.Account] == nil {
				e.fence[en.intent.Account] = map[string]bool{}
			}
			e.fence[en.intent.Account][en.intent.ID] = true
		}
	}
	e.pinned = false
	e.trim()
	return e, nil
}

// Submit records a new intent. Resubmitting the same ID with identical
// fields returns the current state; with any field changed it is ErrConflict
// (OP-1).
func (e *Engine) Submit(in Intent) (Status, error) {
	if in.ID == "" || in.Origin == "" || in.Account == "" || in.Action == "" {
		return Status{}, fmt.Errorf("%w: id, origin, account, and action are required", ErrInvalid)
	}
	if _, ok := e.execs[in.Executor]; !ok {
		return Status{}, fmt.Errorf("%w: unknown executor %q", ErrInvalid, in.Executor)
	}
	norm, err := normalize(in)
	if err != nil {
		return Status{}, err
	}
	if b, _ := json.Marshal(norm); len(b) > MaxIntentBytes {
		return Status{}, fmt.Errorf("%w: intent is %d bytes, limit %d", ErrInvalid, len(b), MaxIntentBytes)
	}
	// Compare in the form the journal stores: redacted, then round-tripped.
	raw := norm
	if norm, err = normalize(e.scrubIntent(raw)); err != nil {
		return Status{}, err
	}
	fp := fingerprint(norm)
	known := func(en *entry) (Status, error) {
		if en.fp != fp {
			return Status{}, fmt.Errorf("%w: %s", ErrConflict, norm.ID)
		}
		return en.status(), nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken != nil {
		return Status{}, e.broken
	}
	if en, ok := e.intents[norm.ID]; ok {
		return known(en)
	}
	if cv, ok := e.cold[coldKeyOf(norm.ID)]; ok {
		// An evicted denial answers from memory, without the journal.
		if cv.fp != fpPrefix(fp) {
			return Status{}, fmt.Errorf("%w: %s", ErrConflict, norm.ID)
		}
		return e.coldStatus(norm.ID, cv), nil
	}
	if err := e.commit(Record{Type: RecSubmitted, ID: raw.ID, Intent: &raw}); err != nil {
		return Status{}, err
	}
	return e.intents[norm.ID].status(), nil
}

// Authorize asks the policy whether a pending intent may run.
func (e *Engine) Authorize(ctx context.Context, id string) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	en, err := e.lookup(id, false)
	if err != nil {
		return Status{}, err
	}
	if en.state != Pending {
		return en.status(), fmt.Errorf("%w: %s is %s", ErrState, id, en.state)
	}
	in := en.intent
	e.mu.Unlock()
	perr := e.policy.Check(ctx, PhaseAuthorize, in)
	e.mu.Lock()
	if en.state != Pending {
		return en.status(), fmt.Errorf("%w: %s is %s", ErrState, id, en.state)
	}
	r := Record{Type: RecAuthorized, ID: id}
	if perr != nil {
		r = Record{Type: RecDenied, ID: id, Reason: perr.Error(), Guest: guestText(perr)}
	}
	if err := e.commit(r); err != nil {
		return Status{}, err
	}
	return en.status(), nil
}

// guestText is a refusal's text for the guest: GuestText when err is
// guesterr.Safe by its own method set, so a Safe error wrapped with other
// text is not; otherwise none, and the guest is given a ref (SR2-3j). The
// interface is matched structurally, keeping journal free of broker
// imports (ARC-2); guesterr's allowlist test bounds which types have it.
func guestText(err error) string {
	if s, ok := err.(interface{ GuestText() string }); ok {
		return s.GuestText()
	}
	return ""
}

// Dispatch runs one attempt of an authorized intent, or a new attempt of one
// whose previous attempt has evidence that it did not take effect. The
// policy is rechecked, and the decision is committed only if nothing was
// journaled meanwhile; the attempt is journaled durably before the executor
// is called (OP-3).
func (e *Engine) Dispatch(ctx context.Context, id string) (Status, error) {
	var (
		en   *entry
		exec Executor
		in   Intent
		n    int
	)
	for try := 0; ; try++ {
		e.mu.Lock()
		var err error
		if en, exec, err = e.dispatchable(id); err != nil {
			var se *SupersededError
			if errors.As(err, &se) && se.Rival == Succeeded {
				// The effect went as se.By after this request was made,
				// which is final: the request is answered, not left
				// authorized (holding a scope bound's place and the
				// sleeper awake) for ever.
				if cerr := e.commit(Record{Type: RecRecheckFailed, ID: id, Reason: err.Error(), Guest: supersededGuest}); cerr != nil {
					e.mu.Unlock()
					return Status{}, cerr
				}
			}
			st := Status{}
			if en != nil {
				st = en.status()
			}
			e.mu.Unlock()
			return st, err
		}
		seq := e.seq
		in = en.intent
		e.mu.Unlock()

		perr := e.policy.Check(ctx, PhaseDispatch, in)

		e.mu.Lock()
		if e.seq != seq {
			// Something was journaled during the check: a STOP, a grant
			// change, another dispatch. Check again against the new state.
			st := en.status()
			e.mu.Unlock()
			if try >= maxRechecks {
				return st, ErrBusy
			}
			continue
		}
		if perr != nil {
			err := e.commit(Record{Type: RecRecheckFailed, ID: id, Reason: perr.Error(), Guest: guestText(perr)})
			st := en.status()
			e.mu.Unlock()
			if err != nil {
				return Status{}, err
			}
			return st, fmt.Errorf("%w: %v", ErrRecheck, perr)
		}
		n = len(en.attempts) + 1
		if err := e.commit(Record{Type: RecDispatched, ID: id, Attempt: n}); err != nil {
			e.mu.Unlock()
			return Status{}, err
		}
		e.mu.Unlock()
		break
	}

	out := safeCall(func() Outcome { return exec.Execute(ctx, in, n) })

	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.commit(Record{Type: RecObserved, ID: id, Attempt: n, Result: out.Result,
		Source: "executor", Evidence: out.Evidence}); err != nil {
		return Status{}, err
	}
	return en.status(), nil
}

// maxRechecks bounds how often Dispatch re-runs the policy check when the
// journal keeps changing under it.
const maxRechecks = 16

// dispatchable returns the intent and its executor if a new attempt may
// start now. Called with e.mu held.
func (e *Engine) dispatchable(id string) (*entry, Executor, error) {
	en, err := e.lookup(id, false)
	if err != nil {
		return nil, nil, err
	}
	// An unclear intent (an earlier parked attempt still unknown) is
	// outcome_unknown, so only the owner's RETRY tries it again.
	if en.state != Authorized && en.state != NotApplied {
		return en, nil, fmt.Errorf("%w: %s is %s", ErrState, id, en.state)
	}
	exempt := narrowing(en.intent)
	if e.stopped && !exempt {
		return en, nil, ErrStopped
	}
	// Unlike mayDispatch, the intent's own place in the fence counts too.
	if len(e.fence[en.intent.Account]) > 0 && !exempt {
		return en, nil, fmt.Errorf("%w: %s", ErrUnreconciled, en.intent.Account)
	}
	// Everything else, the same-effect rules (OP-2) included, is what
	// every path to execution checks (mayDispatch). A held intent stays
	// authorized behind the earlier one (see Waiting).
	if err := e.mayDispatch(en, true); err != nil {
		return en, nil, err
	}
	return en, e.execs[en.intent.Executor], nil
}

// duplicateOf returns an unresolved intent with the same effect as en
// under another ID (unresolved, an earlier parked attempt included), or
// "". Since every new attempt waits for it, two intents with one effect
// are never unresolved together. Called with e.mu held.
func (e *Engine) duplicateOf(en *entry) string {
	var first *entry
	for _, o := range e.byEffect[en.efp] {
		if o != en && o.unresolved() &&
			(first == nil || o.seq < first.seq) {
			first = o
		}
	}
	if first == nil {
		return ""
	}
	return first.intent.ID
}

// rivals reports whether a and b, two intents with the same effect, are
// alternatives for one send of it rather than two sends. They are when
// some intent z with that effect had an attempt proved not applied, by a
// check through the same tool or by its executor, and each of a and b is
// z itself or was submitted after z's first dispatch: a resubmission of
// an effect that did not go, or of one whose outcome was still open, and
// the two may not both go (OP-2, B7). A request made before z was first
// dispatched cannot be a resubmission of it, so it stays a separate
// send, from z and from z's resubmissions alike. The fields are set once,
// from the journal, so a restart sees the same rivals. Requests made
// before any such z was dispatched, and repeats of a send nothing proved
// not applied, stay separate sends, as before. bucket is the intents
// with the effect (byEffect).
func rivals(bucket []*entry, a, b *entry) bool {
	for _, z := range bucket {
		if z.provedSeq != 0 && z.firstDispatchSeq != 0 && resubmits(z, a) && resubmits(z, b) {
			return true
		}
	}
	return false
}

// resubmits reports whether x is z or was submitted after z's first dispatch.
func resubmits(z, x *entry) bool { return x == z || z.firstDispatchSeq < x.seq }

// blocks reports whether rival o holds back a new attempt of en, a
// strict precedence that never leaves two rivals waiting for each other:
//   - one that went (wentSeq) holds back a rival submitted before it went,
//     whatever it does later; a request made after the effect went is a
//     new send, so a fixed owner setting that once failed can be set
//     again and a recurring payment is never refused for good (B8, P6);
//   - one that may have gone or is going (outcome_unknown, parked
//     included, or in flight) holds back every rival until it settles;
//   - one pending or authorized, waiting for approval or dispatch, holds
//     back a rival whose latest attempt was proved not applied (a resend
//     of a not-done effect, or a guest's repeat of a refused request), so
//     of two resubmissions the first dispatched goes; not a first
//     dispatch, and not the owner's retry of a parked rival, which the
//     waiting one is itself held behind (duplicateOf, R11);
//   - one whose latest attempt was proved not applied, from any source,
//     or that was denied, holds back nothing.
func blocks(o, en *entry) bool {
	if (o.wentSeq != 0 && en.seq < o.wentSeq) || o.unresolved() {
		return true
	}
	switch o.state {
	case Pending, Authorized:
		return en.state == NotApplied
	}
	return false
}

// unresolved reports an attempt in flight or with an unknown outcome,
// the latest or an earlier one (unclear, which is outcome_unknown too).
func (en *entry) unresolved() bool {
	return en.state == InFlight || en.state == OutcomeUnknown
}

// sameEffect is the effect-level invariant (OP-2): an intent may start a
// new attempt of its effect only while no rival (rivals) blocks it
// (blocks): every rival is proved not done or denied, or, for a first
// dispatch, waiting for its own. Whichever rival dispatches first goes,
// under the lock, and the others are then refused; a rival proved not
// done never holds another back, so a not-done effect is offered again
// rather than dropped (NotResent). Erased intents keep their effect
// fingerprint (RecErased) and count. An intent that only takes
// authority away (narrowing: a pause, a revoke, a lower budget, loops or
// sharing off) is exempt, as it is from STOP and the fence: applying it
// again cannot widen anything (ADP-9, B8). It returns the first blocking
// rival, or nil. Called with e.mu held.
func (e *Engine) sameEffect(en *entry) *entry {
	if narrowing(en.intent) {
		return nil
	}
	bucket := e.byEffect[en.efp]
	var first *entry
	for _, o := range bucket {
		if o != en && blocks(o, en) && rivals(bucket, en, o) && (first == nil || o.seq < first.seq) {
			first = o
		}
	}
	return first
}

// supersededBy returns the ID of sameEffect(en), or "". NotResent leaves
// en out while it is set, and every dispatch path refuses en
// (mayDispatch). It is computed, not stored, because the rival may later
// be proved not done or be denied, and en is then offered again. Called
// with e.mu held.
func (e *Engine) supersededBy(en *entry) string {
	if o := e.sameEffect(en); o != nil {
		return o.intent.ID
	}
	return ""
}

// index adds en to byEffect under its current effect fingerprint, and
// unindex removes it from under efp. Called with e.mu held.
func (e *Engine) index(en *entry) { e.byEffect[en.efp] = append(e.byEffect[en.efp], en) }

func (e *Engine) unindex(en *entry, efp string) {
	b := e.byEffect[efp]
	for i, o := range b {
		if o == en {
			b = append(b[:i:i], b[i+1:]...)
			break
		}
	}
	if len(b) == 0 {
		delete(e.byEffect, efp)
	} else {
		e.byEffect[efp] = b
	}
}

// SupersededError says an intent was not dispatched because a rival with
// the same effect has gone, may have gone, or is waiting to go under
// another ID (sameEffect): the effect would otherwise go twice. It
// matches ErrState with errors.Is: the intent is no longer waiting for a
// retry.
type SupersededError struct {
	ID string
	By string
	// Rival says what By did: Succeeded when it went after ID was
	// submitted (final), Pending or Authorized when it waits to go, and
	// InFlight or OutcomeUnknown when it may have gone. Empty when not
	// known.
	Rival State
}

func (s *SupersededError) Error() string {
	return fmt.Sprintf("journal: %s is not sent: the same effect went, may have gone, or waits to go as %s", s.ID, s.By)
}

func (s *SupersededError) Is(target error) bool { return target == ErrState }

// supersededGuest is the guest's text for a request denied because the
// same effect already went under another request: fixed words, no IDs.
const supersededGuest = "the same effect already went under another request"

// HeldError says an intent is held behind an unresolved intent with the
// same effect. It matches ErrUnreconciled with errors.Is.
type HeldError struct {
	ID        string
	BlockedBy string
}

func (h *HeldError) Error() string {
	return fmt.Sprintf("%v: %s has the same effect as %s, whose outcome is unknown; "+
		"%s runs once evidence shows %s did not happen, and is unneeded if it did",
		ErrUnreconciled, h.ID, h.BlockedBy, h.ID, h.BlockedBy)
}

func (h *HeldError) Is(target error) bool { return target == ErrUnreconciled }

// Wait describes an authorized intent that cannot dispatch yet and why.
type Wait struct {
	ID string
	// BlockedBy lists the unresolved intents it waits for: a same-effect
	// intent (OP-2) or the intents fencing its account after a restart
	// (OP-4). Resolving them, by Reconcile or by owner evidence through
	// Resolve, releases it.
	BlockedBy []string
	Duplicate bool // waiting on a same-effect intent, not only a fence
}

// Waiting lists authorized intents held behind unresolved ones, so the
// owner can see a retry that is waiting rather than lost.
func (e *Engine) Waiting() []Wait {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Wait
	for _, en := range bySeq(e.open) {
		id := en.intent.ID
		if en.state != Authorized && en.state != NotApplied {
			continue
		}
		var w Wait
		if oid := e.duplicateOf(en); oid != "" {
			w.BlockedBy, w.Duplicate = append(w.BlockedBy, oid), true
		}
		if !narrowing(en.intent) {
			for fid := range e.fence[en.intent.Account] {
				if len(w.BlockedBy) == 0 || w.BlockedBy[0] != fid {
					w.BlockedBy = append(w.BlockedBy, fid)
				}
			}
		}
		if len(w.BlockedBy) > 0 {
			w.ID = id
			sort.Strings(w.BlockedBy)
			out = append(out, w)
		}
	}
	return out
}

// ReconcileReport lists intents reconciliation resolved, those it could
// not, and those it parked in this round. A parked intent is checked again
// on later rounds but is not unresolved: the engine has stopped trying to
// settle it (OP-2).
type ReconcileReport struct {
	Resolved   []string
	Unresolved []string
	Parked     []string
	// Redispatched lists intents whose check proved the effect was not
	// done and that were dispatched again under the dispatch recheck.
	Redispatched []string
}

// parkAfter is how many checks in a row may leave an outcome unknown
// before the intent is parked for the daily digest. At the daemon's
// settle pacing that is about thirteen minutes (OP-2, D-116).
const parkAfter = 10

// Reconcile settles every outcome_unknown attempt in the order OP-2 sets:
// it checks through the same tool (the executor's Reconcile); if the check
// cannot tell and the executor's service honours the idempotency key, it
// executes the same attempt again under the same key; and once parkAfter
// checks in a row have left the outcome unknown, it parks the intent for
// the daily digest. It never starts a new attempt and never asks the
// owner. Checks only read from services, so they run even while stopped;
// a key retry is a dispatch and does not.
func (e *Engine) Reconcile(ctx context.Context) ReconcileReport {
	e.mu.Lock()
	type job struct {
		in     Intent
		n      int
		exec   Executor
		parked bool
	}
	var jobs []job
	for _, en := range bySeq(e.open) {
		// The attempt checked is the unknown one: the latest, or the
		// parked one an owner's retry that did not go left behind
		// (unclear), checked as any parked one is.
		if a := en.outstanding(); en.state == OutcomeUnknown && a != nil {
			jobs = append(jobs, job{en.intent, a.N, e.execs[en.intent.Executor], a.Parked})
		}
	}
	e.mu.Unlock()

	var rep ReconcileReport
	for _, j := range jobs {
		out := Outcome{Result: ResultUnknown}
		if j.exec != nil {
			out = safeCall(func() Outcome { return j.exec.Reconcile(ctx, j.in, j.n) })
		}
		checked := out.Result
		parkNow := false
		if out.Result == ResultUnknown && !j.parked {
			out, parkNow = e.keyRetry(ctx, j.in.ID, j.n, j.exec)
		}
		switch {
		case out.Result == ResultSucceeded || out.Result == ResultNotApplied:
			if checked == ResultNotApplied {
				e.holdFence(j.in.ID, true)
			}
			if _, err := e.Resolve(j.in.ID, j.n, out, SourceReconcile); err != nil && !e.settled(j.in.ID, j.n) {
				e.holdFence(j.in.ID, false)
				if !j.parked {
					rep.Unresolved = append(rep.Unresolved, j.in.ID)
				}
				continue
			}
			e.forget(j.in.ID)
			rep.Resolved = append(rep.Resolved, j.in.ID)
			if checked == ResultNotApplied && e.redispatch(ctx, j.in.ID, j.n) {
				rep.Redispatched = append(rep.Redispatched, j.in.ID)
			}
			e.holdFence(j.in.ID, false)
		case j.parked:
			// Checked again; still unclear. It stays in the digest.
		default:
			if e.park(j.in.ID, j.n, parkNow) {
				rep.Parked = append(rep.Parked, j.in.ID)
			} else {
				rep.Unresolved = append(rep.Unresolved, j.in.ID)
			}
		}
	}
	return rep
}

// holdFence keeps id in its account's restart fence while hold is set,
// through the record that settles it, and lifts it when hold is cleared.
func (e *Engine) holdFence(id string, hold bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if hold {
		e.redispatching[id] = true
		return
	}
	if !e.redispatching[id] {
		return
	}
	delete(e.redispatching, id)
	if en, ok := e.intents[id]; ok && (!en.unresolved() || en.parked()) {
		if f := e.fence[en.intent.Account]; f != nil {
			delete(f, id)
		}
	}
}

// settled reports whether attempt n of id already has evidence, as when a
// key retry observed it itself.
func (e *Engine) settled(id string, n int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	en, err := e.lookup(id, false)
	if err != nil {
		return false
	}
	a := en.attempt(n)
	return a != nil && (a.Result == ResultSucceeded || a.Result == ResultNotApplied)
}

// forget drops id's check count.
func (e *Engine) forget(id string) {
	e.mu.Lock()
	delete(e.checks, id)
	e.mu.Unlock()
}

// park counts one more check that left attempt n of id unknown, and parks
// the intent once parkAfter checks in a row have, or at once when now is
// set (a key retry the clock cannot vouch for). It reports whether it
// parked the intent now.
func (e *Engine) park(id string, n int, now bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	en, err := e.lookup(id, false)
	if err != nil || en.state != OutcomeUnknown {
		return false
	}
	if a := en.outstanding(); a == nil || a.Parked || a.N != n {
		return false
	}
	e.checks[id]++
	reason := "no check through the same tool, and no idempotency key, settled it"
	if now {
		reason = "no check through the same tool settled it, and the clock is behind the journal, so the idempotency key may be forgotten"
	} else if e.checks[id] < parkAfter {
		return false
	}
	if err := e.commit(Record{Type: RecParked, ID: id, Attempt: n, Reason: reason}); err != nil {
		return false
	}
	delete(e.checks, id)
	return true
}

// errClockBehind refuses a key retry when the clock is behind the
// attempt's dispatch or the newest journal record: it went back, so it
// cannot say the service still remembers the key.
var errClockBehind = errors.New("journal: the clock is behind the journal")

// keyRetry executes attempt n of id again under the same idempotency key,
// if the executor reports that its service honours the key and the
// attempt may be dispatched now: not stopped, no same-effect intent ahead
// of it, and the policy's dispatch recheck passes (OP-3). A refused or
// skipped retry journals nothing and returns unknown; the outcome of a
// retry that ran is journaled here and returned. park reports that the
// retry was refused because the clock is not trusted (errClockBehind):
// the intent is then parked at once rather than retried later.
func (e *Engine) keyRetry(ctx context.Context, id string, n int, exec Executor) (out Outcome, park bool) {
	unknown := Outcome{Result: ResultUnknown}
	kh, ok := exec.(KeyHonouring)
	if !ok {
		return unknown, false
	}
	e.mu.Lock()
	en, err := e.lookup(id, false)
	if err != nil {
		e.mu.Unlock()
		return unknown, false
	}
	in := en.intent
	e.mu.Unlock()
	if !safeBool(func() bool { return kh.HonoursKey(in) }) {
		return unknown, false
	}
	life := keyLifetime(exec, in)
	_, err = e.rechecked(ctx, id, func(en *entry) (Record, error) {
		last := en.outstanding()
		if en.state != OutcomeUnknown || last == nil || last.Parked || last.N != n {
			return Record{}, ErrState
		}
		// The service forgets the key after its lifetime; a retry then
		// could apply the effect again. An attempt with no dispatch
		// time counts as expired. A clock that went back behind the
		// journal's newest record, which is at or after the attempt's
		// dispatch record, is not trusted to measure the lifetime (as
		// maintain's Loop3 does not trust one behind its last attempt).
		now := e.now()
		if now.Before(e.newest) {
			return Record{}, fmt.Errorf("%w: %s attempt %d", errClockBehind, id, n)
		}
		if last.Dispatched.IsZero() || now.Sub(last.Dispatched) > life {
			return Record{}, fmt.Errorf("%w: %s attempt %d is past its key's lifetime", ErrState, id, n)
		}
		return Record{Type: RecDispatched, ID: id, Attempt: n, Source: DispatchKey}, e.mayDispatch(en, false)
	})
	if err != nil {
		return unknown, errors.Is(err, errClockBehind)
	}
	out = safeCall(func() Outcome { return exec.Execute(ctx, in, n) })
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.commit(Record{Type: RecObserved, ID: id, Attempt: n, Result: out.Result,
		Source: "executor", Evidence: out.Evidence}); err != nil {
		return unknown, false
	}
	return out, false
}

// redispatch dispatches id again after a check through the same tool
// proved that attempt n did not take effect (OP-2 step 2). It is an
// ordinary new attempt under the dispatch recheck (OP-3): a refused
// recheck journals nothing and leaves the intent not_applied, unlike
// Dispatch, which would deny it. NotResent then lists it for the digest
// and RETRY. It reports whether the attempt ran.
func (e *Engine) redispatch(ctx context.Context, id string, n int) bool {
	_, err := e.Resend(ctx, id, n)
	return err == nil
}

// Resend sends id again after a check through the same tool proved that
// its attempt n did not take effect (OP-2 step 2): the engine's own
// redispatch, or the owner's RETRY of an effect NotResent lists. It is
// an ordinary new attempt and needs what any dispatch needs (no STOP, no
// restart fence on the account, no same-effect intent unresolved ahead
// of it, and the policy's dispatch recheck). A refusal journals nothing
// and leaves the intent not_applied. Since the check proved attempt n
// did not go, the effect happens at most once; and since an intent with
// a live rival is refused (sameEffect, SupersededError), it does not go
// twice under another ID either.
func (e *Engine) Resend(ctx context.Context, id string, n int) (Status, error) {
	var next int
	in, err := e.rechecked(ctx, id, func(en *entry) (Record, error) {
		if !en.notDone() || en.latest().N != n {
			return Record{}, fmt.Errorf("%w: %s attempt %d is %s and not proved not done", ErrState, id, n, en.state)
		}
		next = len(en.attempts) + 1
		return Record{Type: RecDispatched, ID: id, Attempt: next}, e.mayDispatch(en, true)
	})
	if err != nil {
		return Status{}, err
	}
	e.mu.Lock()
	exec := e.execs[in.Executor]
	e.mu.Unlock()
	out := safeCall(func() Outcome { return exec.Execute(ctx, in, next) })
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.commit(Record{Type: RecObserved, ID: id, Attempt: next, Result: out.Result,
		Source: "executor", Evidence: out.Evidence}); err != nil {
		return Status{}, err
	}
	en, err := e.lookup(id, false)
	if err != nil {
		return Status{}, err
	}
	return en.status(), nil
}

// mayDispatch checks, with e.mu held, what every dispatch of en needs
// beyond its own state: no STOP and no restart fence on its account
// (narrowing intents excepted), the effect-level invariant (sameEffect)
// when the dispatch starts a new attempt (again; a key retry repeats an
// attempt under its own key, which the service applies at most once), no
// same-effect intent unresolved ahead of it (OP-2), and a registered
// executor. It is the one place Dispatch, Resend (the engine's redispatch
// and the owner's RETRY of a not-done effect), Retry and the key retry
// all pass, under the lock and again after the policy recheck, so a
// rival that dispatched meanwhile is seen.
func (e *Engine) mayDispatch(en *entry, again bool) error {
	exempt := narrowing(en.intent)
	if e.stopped && !exempt {
		return ErrStopped
	}
	for fid := range e.fence[en.intent.Account] {
		if fid != en.intent.ID && !exempt {
			return fmt.Errorf("%w: %s", ErrUnreconciled, en.intent.Account)
		}
	}
	// An intent that went, by an attempt a check settled after a later
	// one, is not sent again.
	if again && en.wentSeq != 0 {
		return fmt.Errorf("%w: %s already went", ErrState, en.intent.ID)
	}
	// A rival that went after en was requested (even with a later
	// attempt of its own still open: final), waits to go, or (for a
	// resend of a not-done effect) may have gone supersedes en. One whose
	// outcome is unknown holds a fresh intent instead (HeldError, below):
	// it runs if that one is proved not done.
	if o := e.sameEffect(en); again && o != nil {
		went := o.wentSeq != 0 && en.seq < o.wentSeq
		if went || en.notDone() || !o.unresolved() {
			rival := o.state
			if went {
				rival = Succeeded
			}
			return &SupersededError{ID: en.intent.ID, By: o.intent.ID, Rival: rival}
		}
	}
	if oid := e.duplicateOf(en); oid != "" {
		return &HeldError{ID: en.intent.ID, BlockedBy: oid}
	}
	if _, ok := e.execs[en.intent.Executor]; !ok {
		return fmt.Errorf("%w: %q", ErrNoExecutor, en.intent.Executor)
	}
	return nil
}

// rechecked runs the policy's dispatch recheck for id without the lock,
// and commits the record build returns only if build still passes after
// the check and nothing was journaled while it ran. A failed recheck is
// ErrRecheck and journals nothing: the intent keeps its unknown outcome.
// It returns the record committed and the intent as it was then.
func (e *Engine) rechecked(ctx context.Context, id string, build func(*entry) (Record, error)) (Intent, error) {
	for try := 0; ; try++ {
		e.mu.Lock()
		en, err := e.lookup(id, false)
		if err == nil {
			_, err = build(en)
		}
		if err != nil {
			e.mu.Unlock()
			return Intent{}, err
		}
		seq, in := e.seq, en.intent
		e.mu.Unlock()

		perr := e.policy.Check(ctx, PhaseDispatch, in)

		e.mu.Lock()
		if e.seq != seq {
			e.mu.Unlock()
			if try >= maxRechecks {
				return Intent{}, ErrBusy
			}
			continue
		}
		if perr != nil {
			e.mu.Unlock()
			return Intent{}, fmt.Errorf("%w: %v", ErrRecheck, perr)
		}
		rec, err := build(en)
		if err == nil {
			err = e.commit(rec)
		}
		e.mu.Unlock()
		return in, err
	}
}

// Retry runs a parked intent again because the owner asked for it (OP-2):
// a new attempt, under a new idempotency key, so the effect may happen
// twice; the owner's request says so. It needs what any dispatch needs (no
// STOP, no restart fence on the account, no same-effect intent unresolved
// ahead of it, and the policy's dispatch recheck), and a refusal journals
// nothing, so the intent stays parked. parked is the attempt the owner
// was asked about (ParkedIntent.Attempt): an approval of an older request
// does not retry an attempt that was itself a retry.
func (e *Engine) Retry(ctx context.Context, id string, parked int) (Status, error) {
	var n int
	in, err := e.rechecked(ctx, id, func(en *entry) (Record, error) {
		if !en.retryable() || en.latest().N != parked {
			return Record{}, fmt.Errorf("%w: %s attempt %d is %s and not parked", ErrState, id, parked, en.state)
		}
		n = len(en.attempts) + 1
		return Record{Type: RecDispatched, ID: id, Attempt: n, Source: DispatchOwner}, e.mayDispatch(en, true)
	})
	if err != nil {
		return Status{}, err
	}
	exec := e.execs[in.Executor]
	out := safeCall(func() Outcome { return exec.Execute(ctx, in, n) })
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.commit(Record{Type: RecObserved, ID: id, Attempt: n, Result: out.Result,
		Source: "executor", Evidence: out.Evidence}); err != nil {
		return Status{}, err
	}
	en, err := e.lookup(id, false)
	if err != nil {
		return Status{}, err
	}
	return en.status(), nil
}

// ParkedIntent is an intent whose outcome stayed unknown and that the
// engine no longer tries to settle: the daily digest lists it, and the
// owner may ask to retry it (OP-2). Intent keeps its parameters so the
// owner's request can be built from verified facts; they reach the owner
// only through the gate's verifiers, never raw.
type ParkedIntent struct {
	Intent Intent
	// Attempt is the latest attempt, which a retry follows: the parked
	// one, or for an unclear intent the owner's retry that did not go.
	Attempt    int
	Seq        uint64    // of the RecParked record
	Dispatched time.Time // when the parked attempt was first dispatched
	// NotDone: a check through the same tool proved Attempt did not take
	// effect and it was not sent again (NotResent). Seq is then that
	// check's record. A retry of it cannot go twice.
	NotDone bool
}

// Parked lists the parked intents, oldest first: those whose latest
// attempt is parked, and those whose owner's retry did not go while an
// earlier parked attempt is still unknown (unclear). An intent that went
// by an earlier attempt is left out: nothing would send it again.
func (e *Engine) Parked() []ParkedIntent {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []ParkedIntent
	for _, en := range bySeq(e.open) {
		// One that went by another attempt (the owner's evidence on the
		// parked one) is not sent again (mayDispatch), so not offered.
		if !en.retryable() || en.wentSeq != 0 {
			continue
		}
		// Attempt is the latest, which a retry follows; Dispatched is
		// when the parked attempt that may have gone was sent.
		out = append(out, ParkedIntent{Intent: en.intent, Attempt: en.latest().N, Seq: en.parkedSeq, Dispatched: en.outstanding().Dispatched})
	}
	return out
}

// NotResent lists, oldest first, the intents a check through the same
// tool proved were not done and that were not sent again: the resend was
// refused (STOP, another unresolved intent on the account, a same-effect
// intent ahead of it, or the dispatch recheck, which after a restart
// refuses every effect that needed the owner's approval, since the gate's
// approvals live in memory), or the broker stopped before it. The digest
// names them and RETRY offers them (Resend), so a proven not-done effect
// is never dropped silently (OP-2). An erased intent is not listed: its
// parameters are gone. Nor is one with a live rival (supersededBy): a
// resubmission of the same effect that went, may have gone, or waits for
// approval or dispatch; offering it would send the effect twice. It is
// offered again once that rival is proved not done or denied, and an
// authorized one the settle loop dispatches (Release). One with an
// earlier parked attempt still unknown (unclear) is outcome_unknown, not
// not done: Parked lists it, as only the owner's retry may try it again.
func (e *Engine) NotResent() []ParkedIntent {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []ParkedIntent
	for _, en := range bySeq(e.open) {
		if !en.notDone() || en.erased || e.redispatching[en.intent.ID] || e.supersededBy(en) != "" {
			continue
		}
		last := en.latest()
		out = append(out, ParkedIntent{Intent: en.intent, Attempt: last.N, Seq: en.notDoneSeq, Dispatched: last.Dispatched, NotDone: true})
	}
	return out
}

// Release dispatches, oldest first through dispatch, each authorized
// intent that holds back a not-done effect (an intent NotResent leaves
// out because this rival waits to go): a resubmission made while the
// original's outcome was unknown, held then, which wins over the
// original's resend (blocks). Nothing else dispatches it, and the guest
// that asked was only told to ask again later, so without this the
// effect would wait on the agent (R12). Each goes through the same
// dispatch path as any other (the caller passes the gate's Dispatch,
// which spends the owner's approval, or the engine's), so it is held or
// refused as any dispatch is; one refused at the recheck is denied and
// the original is offered again.
//
// It also answers each authorized intent whose effect went under a rival
// after it was requested (blocks): dispatching it denies it as superseded
// (Dispatch), so it does not hold a scope bound's place or keep the
// sleeper awake until someone happens to dispatch it (R15). It returns
// the intents dispatched (those denied are not listed).
func (e *Engine) Release(ctx context.Context, dispatch func(context.Context, string) (Status, error)) []string {
	e.mu.Lock()
	var ids []string
	seen := map[string]bool{}
	add := func(id string) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, en := range bySeq(e.open) {
		if en.state == Authorized {
			if o := e.sameEffect(en); o != nil && o.wentSeq != 0 && en.seq < o.wentSeq {
				add(en.intent.ID)
			}
		}
		if !en.notDone() || en.erased || e.redispatching[en.intent.ID] {
			continue
		}
		if o := e.sameEffect(en); o != nil && o.state == Authorized {
			add(o.intent.ID)
		}
	}
	e.mu.Unlock()
	var out []string
	for _, id := range ids {
		if _, err := dispatch(ctx, id); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// Queued returns the intents on account with action that are pending or
// authorized: requested, and waiting for approval or dispatch, oldest
// first. The gate's RETRY line counts them as sends that may still go
// (grants GR35).
func (e *Engine) Queued(account, action string) []Intent {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Intent
	for _, en := range bySeq(e.open) {
		if en.intent.Account == account && en.intent.Action == action && (en.state == Pending || en.state == Authorized) {
			out = append(out, en.intent)
		}
	}
	return out
}

// reconcileRound bounds one round of SettleUnknown, so an executor whose
// service hangs is asked again rather than holding the round forever.
const reconcileRound = time.Minute

// SettleUnknown runs Reconcile until no outcome_unknown attempt is left or
// ctx ends, waiting wait after the first unresolved round and doubling up
// to maxWait (OP-4). It only gathers evidence, so no effect runs again: an
// executor that cannot tell what happened answers unknown and its account
// stays fenced, and one whose service is down is asked again on the next
// round. It returns the last round's report.
func (e *Engine) SettleUnknown(ctx context.Context, wait, maxWait time.Duration) ReconcileReport {
	if wait <= 0 {
		wait = time.Millisecond
	}
	for {
		rctx, cancel := context.WithTimeout(ctx, reconcileRound)
		rep := e.Reconcile(rctx)
		cancel()
		e.mu.Lock()
		if len(rep.Unresolved) == 0 {
			e.missed = 0
		} else {
			e.missed++
		}
		e.mu.Unlock()
		if len(rep.Unresolved) == 0 || ctx.Err() != nil {
			return rep
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return rep
		case <-t.C:
		}
		if wait *= 2; wait > maxWait {
			wait = maxWait
		}
	}
}

// Resolve records evidence about an attempt from outside the executor, such
// as the owner confirming what happened. Only succeeded or not_applied
// resolve an attempt; unknown is not evidence (OP-2).
func (e *Engine) Resolve(id string, attempt int, out Outcome, source string) (Status, error) {
	if source == "" {
		return Status{}, fmt.Errorf("%w: evidence needs a source", ErrInvalid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	en, err := e.lookup(id, false)
	if err != nil {
		return Status{}, err
	}
	r := Record{Type: RecObserved, ID: id, Attempt: attempt, Result: out.Result, Source: source, Evidence: out.Evidence}
	if out.Result != ResultSucceeded && out.Result != ResultNotApplied {
		return en.status(), fmt.Errorf("%w: %s is not evidence", ErrState, out.Result)
	}
	// An attempt still in flight belongs to its Dispatch call.
	if a := en.attempt(attempt); a == nil || a.Result != ResultUnknown {
		return en.status(), fmt.Errorf("%w: %s attempt %d is not outcome_unknown", ErrState, id, attempt)
	}
	if err := e.commit(r); err != nil {
		return Status{}, err
	}
	return en.status(), nil
}

// CancelAttempt records one cancellation STOP requested.
type CancelAttempt struct {
	ID        string
	Attempt   int
	Supported bool // the executor implements Canceller
	Accepted  bool // the service accepted the request; not proof of undo
	Detail    string
}

// StopReport is what STOP tells the owner. It has no field for undone
// effects: STOP never claims to undo a remote action (OP-6).
type StopReport struct {
	// Held intents were authorized but not dispatched; RESUME releases them.
	Held []string
	// Unresolved intents may have reached a service: in flight or unknown.
	Unresolved []string
	Cancels    []CancelAttempt
}

// Stop blocks all further dispatch, durably, then requests cancellation of
// every unresolved attempt whose executor supports it, and reports. Once
// Stop returns, an executor can still start only for an attempt that was
// already journaled as dispatched, and that attempt is in Unresolved.
func (e *Engine) Stop(ctx context.Context) (StopReport, error) {
	e.mu.Lock()
	if e.broken != nil {
		e.mu.Unlock()
		return StopReport{}, e.broken
	}
	if err := e.commit(Record{Type: RecStop}); err != nil {
		e.mu.Unlock()
		return StopReport{}, err
	}
	var rep StopReport
	type job struct {
		in Intent
		n  int
	}
	var jobs []job
	for _, en := range bySeq(e.open) {
		if (en.state == Authorized || en.state == NotApplied) && !narrowing(en.intent) {
			rep.Held = append(rep.Held, en.intent.ID)
		}
	}
	// Every attempt that may still take effect is cancelled and its
	// intent reported: an unclear intent's parked attempt, each later one
	// still in flight or unknown (Security R18 on #1433), and an earlier
	// attempt still unknown of an intent a later attempt (the owner's
	// retry) settled as succeeded, which has left the open set (Security
	// R22 on #1433).
	for _, en := range append(bySeq(e.open), bySeq(e.lingering)...) {
		n := len(jobs)
		for _, a := range en.attempts {
			if a.Result == ResultUnknown || a.Result == ResultInFlight {
				jobs = append(jobs, job{en.intent, a.N})
			}
		}
		if len(jobs) > n || en.state == InFlight || en.state == OutcomeUnknown {
			rep.Unresolved = append(rep.Unresolved, en.intent.ID)
		}
	}
	e.mu.Unlock()

	var firstErr error
	for _, j := range jobs {
		ca := CancelAttempt{ID: j.in.ID, Attempt: j.n}
		if c, ok := e.execs[j.in.Executor].(Canceller); ok {
			ca.Supported = true
			func() {
				defer func() {
					if p := recover(); p != nil {
						ca.Accepted, ca.Detail = false, fmt.Sprintf("cancel panicked: %v", p)
					}
				}()
				ca.Accepted, ca.Detail = c.Cancel(ctx, j.in, j.n)
			}()
			e.mu.Lock()
			if err := e.commit(Record{Type: RecCancel, ID: j.in.ID, Attempt: j.n,
				Accepted: ca.Accepted, Evidence: ca.Detail}); err != nil && firstErr == nil {
				firstErr = err
			}
			e.mu.Unlock()
		}
		rep.Cancels = append(rep.Cancels, ca)
	}
	return rep, firstErr
}

// Resume lifts STOP. Authenticating the request (CH-11) is the caller's job.
func (e *Engine) Resume() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken != nil {
		return e.broken
	}
	if !e.stopped {
		return fmt.Errorf("%w: not stopped", ErrState)
	}
	return e.commit(Record{Type: RecResume})
}

// GuestActive reports an intent the agent submitted (origin "guest:")
// that is authorized but not yet dispatched, or in flight: work the agent
// has in hand, so the sleeper does not stop it (PE7 condition 2).
func (e *Engine) GuestActive() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, en := range e.open {
		if strings.HasPrefix(en.intent.Origin, "guest:") && (en.state == Authorized || en.state == InFlight) {
			return true
		}
	}
	return false
}

// Stopped reports whether STOP is in force.
func (e *Engine) Stopped() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopped
}

// RecordQuality records whether an intent served its goal. It never changes
// permission or execution (OP-7).
func (e *Engine) RecordQuality(id string, q Quality) (Status, error) {
	if q.Verdict != VerdictGood && q.Verdict != VerdictWrong {
		return Status{}, fmt.Errorf("%w: verdict %q", ErrInvalid, q.Verdict)
	}
	if q.Source == "" {
		return Status{}, fmt.Errorf("%w: verdict needs a source", ErrInvalid)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	en, err := e.lookup(id, true)
	if err != nil {
		return Status{}, err
	}
	if err := e.commit(Record{Type: RecQuality, ID: id, Verdict: q.Verdict, Source: q.Source, Evidence: q.Note}); err != nil {
		return Status{}, err
	}
	return en.status(), nil
}

// Get returns one intent's status. An evicted denial answers from memory
// without its params, recipients or other free-form fields; List, Between,
// StatusBetween and Trail read them from the journal.
func (e *Engine) Get(id string) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if en, ok := e.intents[id]; ok {
		return en.status(), nil
	}
	if cv, ok := e.cold[coldKeyOf(id)]; ok {
		return e.coldStatus(id, cv), nil
	}
	return Status{}, fmt.Errorf("%w: %s", ErrNotFound, id)
}

// List returns every intent in submission order.
func (e *Engine) List() []Status {
	var out []Status
	e.each(func(en *entry) { out = append(out, en.status()) })
	return out
}

// each calls f on every intent in submission order. While none has been
// evicted it reads memory, under the lock; otherwise it replays the
// journal into private entries, without the lock. If the journal cannot be
// read it falls back to memory, which lacks the evicted denials. f must
// not call the engine.
func (e *Engine) each(f func(*entry)) {
	e.mu.Lock()
	if len(e.cold) > 0 {
		e.mu.Unlock()
		if ens, err := e.journalEntries(nil); err == nil {
			for _, en := range ens {
				f(en)
			}
			return
		}
		e.mu.Lock()
	}
	defer e.mu.Unlock()
	for _, en := range bySeq(e.intents) {
		f(en)
	}
}

// AuthorizedSince returns the intents on account with action that were
// authorized at or after since and not later denied by the recheck, oldest
// first. Pre-allowance scope bounds count them (ADP-9): an authorized intent
// holds its place in the bound until the recheck before dispatch refuses it.
func (e *Engine) AuthorizedSince(account, action string, since time.Time) []Intent {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Intent
	for _, en := range bySeq(e.intents) {
		if en.intent.Account != account || en.intent.Action != action || en.state == Denied || en.authorized.IsZero() {
			continue
		}
		if !en.authorized.Before(since) {
			out = append(out, en.intent)
		}
	}
	return out
}

// Use is one intent's place under a pre-allowance scope bound (ADP-9).
type Use struct {
	Intent Intent
	// Started: an attempt has been dispatched and was not shown to have
	// done nothing. Otherwise the intent is authorized and waiting.
	Started bool
	// Erased: its content was removed under CAP-3, so Intent.Params no
	// longer names its record; a scope bound counts it against every
	// record (SR3-2-f3).
	Erased bool
	// Dispatched is when its latest attempt was dispatched (zero if none).
	Dispatched time.Time
	// Went is when the attempt known to have gone was dispatched, zero
	// unless one of its attempts was observed succeeded: a known success
	// (the gate's confirm-repeats rule, D-116).
	Went time.Time
	// Known is when that success became known: the later of Went and
	// when the journal recorded the observation, so a success a check
	// proves a day after its dispatch counts from the proof (Security
	// B11 on #1433). Zero when Went is.
	Known time.Time
	// Tried is when the attempt that may still take effect (in flight or
	// unknown) was first dispatched, zero for any other state: for an
	// unclear intent, its parked try, not the owner's retry that did not
	// go (Security R19 on #1433).
	Tried time.Time
}

// InUse returns the intents on account with action that hold a place
// under a scope bound counted from since, oldest first (SR3-2). A place is
// charged when an effect may start, not when it was authorized, so an
// intent queued past its authorization's day cannot run outside the bound:
//   - authorized and not yet dispatched: reserved, whatever its age, until
//     it is dispatched or refused at the recheck;
//   - its latest attempt in flight or outcome_unknown: held until evidence
//     resolves it (OP-2), whatever its age;
//   - its latest attempt succeeded: charged to the window it was
//     dispatched in, so counted while that is at or after since, and
//     also while its success became known at or after since (Use.Known):
//     a success proved late counts from its proof, which only counts
//     more (Security B11 on #1433).
//
// An attempt that did not apply releases its place; a retry takes one
// again when it is dispatched.
func (e *Engine) InUse(account, action string, since time.Time) []Use {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Use
	for _, en := range bySeq(e.intents) {
		if en.intent.Account != account || en.intent.Action != action {
			continue
		}
		switch en.state {
		case Authorized:
			out = append(out, Use{Intent: en.intent})
		case InFlight, OutcomeUnknown:
			// An unclear intent (its owner's retry did not go, an earlier
			// parked try may have) is outcome_unknown: started (B9).
			out = append(out, Use{Intent: en.intent, Started: true, Erased: en.erased, Dispatched: en.dispatched,
				Went: en.wentAt, Known: en.known(), Tried: en.outstanding().Dispatched})
		case Succeeded:
			if !en.dispatched.Before(since) || !en.known().Before(since) {
				out = append(out, Use{Intent: en.intent, Started: true, Erased: en.erased, Dispatched: en.dispatched,
					Went: en.wentAt, Known: en.known()})
			}
		}
	}
	return out
}

// Trail returns the journal records, oldest first: one audit trail for
// effects and broker-state changes (OP-5). It reads the journal, not
// memory, and is nil if the journal cannot be read.
func (e *Engine) Trail() []Record {
	recs, err := e.ReadTrail()
	if err != nil {
		return nil
	}
	return recs
}

// ReadTrail is Trail with the read error, for a caller that must tell an
// unreadable journal from an empty one (journal/check).
func (e *Engine) ReadTrail() ([]Record, error) { return e.readJournal() }

// RecordsAfter returns the journal records with a sequence number greater
// than seq, oldest first. Records are numbered from 1 with no gaps, so a
// projection that has applied through seq reads its tail here (SIM-proj).
// Like Trail it decodes the journal afresh, so the records share nothing
// with the intents the engine dispatches. Unlike Trail it returns the read
// error, so a projection never mistakes an unreadable journal for an empty
// tail.
func (e *Engine) RecordsAfter(seq uint64) ([]Record, error) {
	recs, err := e.readJournal()
	if err != nil {
		return nil, err
	}
	if seq >= uint64(len(recs)) {
		return nil, nil
	}
	return recs[seq:], nil
}

// Fenced returns the intents on account that the last restart left
// unresolved and that still are; dispatch on the account waits for them.
func (e *Engine) Fenced(account string) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for id := range e.fence[account] {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Unconfirmed lists the intents the last restart fenced that are still
// unresolved once SettleUnknown has asked for their evidence at least
// rounds times in a row, oldest first, so STATUS can say what is not
// confirmed (#1373). It is empty before then: a fence the first evidence
// lifts is never shown. Parameters and preconditions are left out.
func (e *Engine) Unconfirmed(rounds int) []Intent {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.missed < rounds {
		return nil
	}
	var out []Intent
	for _, en := range bySeq(e.open) {
		if e.fence[en.intent.Account][en.intent.ID] {
			in := en.intent
			in.Params, in.Preconditions = nil, nil
			out = append(out, in)
		}
	}
	return out
}

// lookup finds an intent for a change. An evicted denial is rehydrated
// from the journal only when warm is set (a rating); otherwise it is a
// detached entry that no state change accepts. Caller holds mu.
func (e *Engine) lookup(id string, warm bool) (*entry, error) {
	if e.broken != nil {
		return nil, e.broken
	}
	if en, ok := e.intents[id]; ok {
		return en, nil
	}
	if cv, ok := e.cold[coldKeyOf(id)]; ok && !warm {
		st := e.coldStatus(id, cv)
		return &entry{intent: st.Intent, state: Denied, permission: st.Permission}, nil
	}
	if e.evicted(id) {
		if err := e.rehydrate([]string{id}); err != nil {
			return nil, err
		}
		if en, ok := e.intents[id]; ok {
			return en, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
}

// commit validates a record, makes it durable, then applies it. Live
// operation and replay share validate and apply, so replay reaches exactly
// the state the live engine had. A failed write breaks the engine: in-memory
// state no longer matches the medium, so it refuses everything until
// reopened.
func (e *Engine) commit(r Record) error {
	if e.broken != nil {
		return e.broken
	}
	r = e.scrub(r)
	r.V = recordVersion
	r.Seq = e.seq + 1
	r.At = e.now()
	line, err := encodeRecord(r)
	if err != nil {
		return err
	}
	// Apply exactly what replay will read back, so live and replayed state
	// cannot diverge (e.g. on invalid UTF-8, which JSON rewrites).
	stored, err := decodeLine(line[:len(line)-1])
	if err != nil {
		return err
	}
	if err := e.validate(stored); err != nil {
		return fmt.Errorf("%w: %v", ErrState, err)
	}
	if err := e.store.Append(line); err != nil {
		e.broken = fmt.Errorf("%w: %v", ErrBroken, err)
		return e.broken
	}
	e.apply(stored)
	e.trim()
	return nil
}

// validate checks that a record is a legal transition from the current state.
func (e *Engine) validate(r Record) error {
	if r.Type == RecStop {
		return nil
	}
	if r.Type == RecEgress {
		if r.Egress == nil || r.Egress.Machine == "" || r.ID != "" {
			return fmt.Errorf("egress record without a machine")
		}
		return nil
	}
	if r.Type == RecSleep {
		if r.Sleep == nil || !r.Sleep.valid() || r.ID != "" {
			return fmt.Errorf("sleep record without a valid note")
		}
		return nil
	}
	if r.Type == RecResume {
		if !e.stopped {
			return fmt.Errorf("resume while not stopped")
		}
		return nil
	}
	en := e.intents[r.ID]
	if r.Type == RecSubmitted {
		if en != nil {
			return fmt.Errorf("duplicate submission of %s", r.ID)
		}
		if r.Intent == nil || r.Intent.ID != r.ID {
			return fmt.Errorf("submission without matching intent")
		}
		return nil
	}
	if en == nil {
		return fmt.Errorf("unknown intent %s", r.ID)
	}
	switch r.Type {
	case RecAuthorized, RecDenied:
		if en.state != Pending {
			return fmt.Errorf("%s: %s from %s", r.ID, r.Type, en.state)
		}
	case RecRecheckFailed:
		// From not_applied too, on purpose: a recheck before a resend
		// of a not-done attempt can fail (OP-3), and Erase denies a
		// not-done intent this way before it erases it (CAP-3).
		if en.state != Authorized && en.state != NotApplied {
			return fmt.Errorf("%s: recheck from %s", r.ID, en.state)
		}
	case RecDispatched:
		if e.stopped && !narrowing(en.intent) {
			return fmt.Errorf("%s: dispatched while stopped", r.ID)
		}
		last := en.latest()
		switch r.Source {
		case "":
			if en.state != Authorized && en.state != NotApplied {
				return fmt.Errorf("%s: dispatched from %s", r.ID, en.state)
			}
			if r.Attempt != len(en.attempts)+1 {
				return fmt.Errorf("%s: attempt %d, want %d", r.ID, r.Attempt, len(en.attempts)+1)
			}
		case DispatchKey:
			// The same attempt again, under the same idempotency key:
			// the unknown one, never a settled retry after it.
			last = en.outstanding()
			if en.state != OutcomeUnknown || last == nil || last.Parked || r.Attempt != last.N {
				return fmt.Errorf("%s: key retry of attempt %d from %s", r.ID, r.Attempt, en.state)
			}
		case DispatchOwner:
			if !en.retryable() || r.Attempt != len(en.attempts)+1 {
				return fmt.Errorf("%s: owner retry as attempt %d from %s", r.ID, r.Attempt, en.state)
			}
		default:
			return fmt.Errorf("%s: dispatch source %q", r.ID, r.Source)
		}
	case RecParked:
		last := en.outstanding()
		if en.state != OutcomeUnknown || last == nil || last.Parked || r.Attempt != last.N {
			return fmt.Errorf("%s: parked attempt %d from %s", r.ID, r.Attempt, en.state)
		}
	case RecObserved:
		a := en.attempt(r.Attempt)
		if a == nil {
			return fmt.Errorf("%s: no attempt %d", r.ID, r.Attempt)
		}
		if a.Result != ResultInFlight && a.Result != ResultUnknown {
			return fmt.Errorf("%s: attempt %d already %s", r.ID, r.Attempt, a.Result)
		}
		switch r.Result {
		case ResultSucceeded, ResultNotApplied:
		case ResultUnknown:
			if a.Result != ResultInFlight {
				return fmt.Errorf("%s: attempt %d already unknown", r.ID, r.Attempt)
			}
		default:
			return fmt.Errorf("%s: result %q", r.ID, r.Result)
		}
	case RecCancel:
		if en.attempt(r.Attempt) == nil {
			return fmt.Errorf("%s: no attempt %d", r.ID, r.Attempt)
		}
		// Only Stop writes these, for an attempt outstanding at a STOP.
		if !e.stoppedAt[attemptRef{r.ID, r.Attempt}] {
			return fmt.Errorf("%s: cancel of attempt %d, not outstanding at a stop", r.ID, r.Attempt)
		}
	case RecQuality:
		if r.Verdict != VerdictGood && r.Verdict != VerdictWrong {
			return fmt.Errorf("%s: verdict %q", r.ID, r.Verdict)
		}
		// Legal from every state, on purpose: goal quality is
		// recorded apart from permission and execution (OP-7) and
		// apply never changes the state or the attempts for it, so
		// no state makes it inconsistent. Owners rate a task before
		// it is dispatched, and journals already hold such records;
		// a state guard here would fail their Open (ErrCorrupt).
	case RecErased:
		if en.state != Succeeded && en.state != Denied {
			return fmt.Errorf("%s: erased from %s", r.ID, en.state)
		}
	default:
		return fmt.Errorf("unknown record type %q", r.Type)
	}
	return nil
}

// apply moves state forward by one validated record.
func (e *Engine) apply(r Record) {
	e.seq = r.Seq
	if r.At.After(e.newest) {
		e.newest = r.At
	}
	switch r.Type {
	case RecStop:
		e.stopped = true
		// What Stop cancels: the open and lingering intents' attempts
		// still in flight or unknown.
		for _, m := range []map[string]*entry{e.open, e.lingering} {
			for id, en := range m {
				for _, a := range en.attempts {
					if a.Result == ResultUnknown || a.Result == ResultInFlight {
						if e.stoppedAt == nil {
							e.stoppedAt = map[attemptRef]bool{}
						}
						e.stoppedAt[attemptRef{id, a.N}] = true
					}
				}
			}
		}
		return
	case RecResume:
		e.stopped = false
		return
	case RecEgress, RecSleep:
		return
	case RecSubmitted:
		en := newEntry(r)
		e.intents[r.ID], e.open[r.ID] = en, en
		e.index(en)
		return
	}
	en := e.intents[r.ID]
	was, efp := en.state, en.efp
	en.apply(r)
	if en.efp != efp {
		// An erase restores the fingerprint the params gave (RecErased).
		e.unindex(en, efp)
		e.index(en)
	}
	if ((r.Type == RecObserved && r.Result != ResultUnknown) || r.Type == RecParked) && !e.redispatching[r.ID] {
		if f := e.fence[en.intent.Account]; f != nil {
			delete(f, r.ID)
		}
	}
	switch en.state {
	case Succeeded, Denied:
		delete(e.open, r.ID)
	default:
		e.open[r.ID] = en
	}
	if en.state == Succeeded && en.mayStillTakeEffect() {
		e.lingering[r.ID] = en
	} else {
		delete(e.lingering, r.ID)
	}
	if en.state == Denied && was != Denied {
		e.denied = append(e.denied, r.ID)
	}
}

// trim evicts the oldest denials past hotDenials. They stay in the journal.
func (e *Engine) trim() {
	if e.pinned {
		return
	}
	for len(e.denied) > hotDenials {
		id := e.denied[0]
		e.denied = e.denied[1:]
		// A rated denial, or one with attempts, stays: only the owner
		// makes those, and coldVal does not carry them.
		if en := e.intents[id]; en != nil && en.state == Denied && len(en.attempts) == 0 && en.quality == (Quality{}) {
			delete(e.intents, id)
			e.unindex(en, en.efp)
			e.cold[coldKeyOf(id)] = e.coldValOf(en)
		}
	}
}

// coldValOf is what stays in memory of an evicted denial. Caller holds mu.
func (e *Engine) coldValOf(en *entry) coldVal {
	in, p := en.intent, en.permission
	sh := coldShape{goal: in.GoalID, origin: in.Origin, account: in.Account, action: in.Action,
		exec: in.Executor, reason: p.Reason, guest: p.GuestReason, phase: p.Phase}
	i, ok := e.shapeIx[sh]
	if !ok {
		i = uint32(len(e.shapes))
		e.shapes = append(e.shapes, sh)
		e.shapeIx[sh] = i
	}
	return coldVal{fp: fpPrefix(en.fp), shape: i}
}

// coldStatus is an evicted denial's status. Caller holds mu.
func (e *Engine) coldStatus(id string, cv coldVal) Status {
	sh := e.shapes[cv.shape]
	in, _ := normalize(Intent{ID: id, GoalID: sh.goal, Origin: sh.origin, Account: sh.account,
		Action: sh.action, Executor: sh.exec})
	return Status{
		Intent:     in,
		State:      Denied,
		Permission: Permission{Decision: "denied", Phase: sh.phase, Reason: sh.reason, GuestReason: sh.guest},
		Attempts:   []Attempt{},
	}
}

// fpPrefix is the first 16 bytes of a hex fingerprint.
func fpPrefix(fp string) (out [16]byte) {
	hex.Decode(out[:], []byte(fp[:min(len(fp), 32)]))
	return out
}

// evicted reports whether id may be an evicted denial. Caller holds mu.
func (e *Engine) evicted(id string) bool {
	_, ok := e.cold[coldKeyOf(id)]
	return ok
}

// rehydrate brings evicted denials back into memory with one journal read,
// for an operation that changes them (a rating, an erase). It reads under
// the lock; guest-facing reads (Get, Submit) never come here. They are
// evicted again in turn. Caller holds mu.
func (e *Engine) rehydrate(ids []string) error {
	want := map[string]bool{}
	for _, id := range ids {
		if e.intents[id] == nil && e.evicted(id) {
			want[id] = true
		}
	}
	if len(want) == 0 {
		return nil
	}
	ens, err := e.journalEntries(func(id string) bool { return want[id] })
	if err != nil {
		return err
	}
	for _, en := range ens {
		e.intents[en.intent.ID] = en
		e.index(en)
		e.denied = append(e.denied, en.intent.ID)
	}
	return nil
}

// readJournal decodes the whole journal. The store serialises its own
// reads and writes, so this needs no engine lock and sees whole records.
func (e *Engine) readJournal() ([]Record, error) {
	data, err := e.store.ReadAll()
	if err != nil {
		return nil, err
	}
	recs, _, err := decodeJournal(data)
	return recs, err
}

// journalEntries replays the journal into fresh entries for the intents
// keep accepts (every intent if keep is nil), in submission order.
func (e *Engine) journalEntries(keep func(id string) bool) ([]*entry, error) {
	recs, err := e.readJournal()
	if err != nil {
		return nil, err
	}
	byID := map[string]*entry{}
	var out []*entry
	for _, r := range recs {
		if r.ID == "" || (keep != nil && !keep(r.ID)) {
			continue
		}
		if r.Type == RecSubmitted {
			en := newEntry(r)
			byID[r.ID] = en
			out = append(out, en)
		} else if en := byID[r.ID]; en != nil {
			en.apply(r)
		}
	}
	return out, nil
}

// bySeq returns the entries of m in submission order.
func bySeq(m map[string]*entry) []*entry {
	out := make([]*entry, 0, len(m))
	for _, en := range m {
		out = append(out, en)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

func newEntry(r Record) *entry {
	in := *r.Intent
	return &entry{seq: r.Seq, intent: in, fp: fingerprint(in), efp: effectFingerprint(in), state: Pending, submitted: r.At}
}

// apply moves one intent forward by a validated record about it. Live
// state and every replay of the journal share it.
func (en *entry) apply(r Record) {
	switch r.Type {
	case RecAuthorized:
		en.state = Authorized
		en.authorized = r.At
		en.permission = Permission{Decision: "allowed", Phase: PhaseAuthorize}
	case RecDenied:
		en.state = Denied
		en.permission = Permission{Decision: "denied", Phase: PhaseAuthorize, Reason: r.Reason, GuestReason: r.Guest}
	case RecRecheckFailed:
		en.state = Denied
		en.permission = Permission{Decision: "denied", Phase: PhaseDispatch, Reason: r.Reason, GuestReason: r.Guest}
	case RecDispatched:
		en.state = InFlight
		en.dispatched = r.At
		if en.firstDispatchSeq == 0 {
			en.firstDispatchSeq = r.Seq
		}
		if r.Source == DispatchKey {
			en.attempt(r.Attempt).Result = ResultInFlight
		} else {
			en.attempts = append(en.attempts, Attempt{N: r.Attempt, Result: ResultInFlight, Dispatched: r.At})
		}
	case RecParked:
		en.attempt(r.Attempt).Parked = true
		en.parkedSeq = r.Seq
	case RecObserved:
		a := en.attempt(r.Attempt)
		a.Result, a.Source, a.Evidence = r.Result, r.Source, r.Evidence
		if r.Source == SourceReconcile && r.Result == ResultNotApplied {
			en.notDoneSeq = r.Seq
		}
		if r.Result == ResultNotApplied && en.provedSeq == 0 {
			en.provedSeq = r.Seq
		}
		if r.Result == ResultSucceeded && en.wentSeq == 0 {
			en.wentSeq = r.Seq
			// The latest attempt's dispatch time includes a same-key
			// retry of it; an earlier attempt has only its own.
			en.wentAt = a.Dispatched
			if r.Attempt == len(en.attempts) {
				en.wentAt = en.dispatched
			}
			en.knownAt = r.At
		}
		en.state = en.derive()
	case RecCancel:
		a := en.attempt(r.Attempt)
		a.Cancels = append(a.Cancels, Cancel{Accepted: r.Accepted, Detail: r.Evidence})
	case RecQuality:
		en.quality = Quality{Verdict: r.Verdict, Source: r.Source, Note: r.Evidence}
	case RecErased:
		en.erased = true
		en.intent.Params, en.intent.Preconditions = nil, nil
		for i := range en.attempts {
			en.attempts[i].Evidence = ""
			for j := range en.attempts[i].Cancels {
				en.attempts[i].Cancels[j].Detail = ""
			}
		}
		if r.FP != "" {
			en.fp, en.efp = r.FP, r.EFP
		}
	}
}

// known is when the intent's success became known (Use.Known): the later
// of the dispatch of the attempt that went and the record observing it,
// zero if none went.
func (en *entry) known() time.Time {
	if en.wentSeq == 0 {
		return time.Time{}
	}
	if en.knownAt.After(en.wentAt) {
		return en.knownAt
	}
	return en.wentAt
}

// mayStillTakeEffect reports an attempt still in flight or unknown.
func (en *entry) mayStillTakeEffect() bool {
	for _, a := range en.attempts {
		if a.Result == ResultUnknown || a.Result == ResultInFlight {
			return true
		}
	}
	return false
}

// latest is the intent's last attempt, or nil before its first.
func (en *entry) latest() *Attempt { return en.attempt(len(en.attempts)) }

// notDone reports whether the intent is not_applied because a check
// through the same tool proved its last attempt did not take effect.
func (en *entry) notDone() bool {
	a := en.latest()
	return en.state == NotApplied && a != nil && a.Result == ResultNotApplied && a.Source == SourceReconcile
}

// derive is the intent's state once an attempt is observed. The state is
// what every reader of an intent goes by (Erase, InUse, STOP, STATUS, the
// recall count, the gate's reports), so it says whether the effect may
// have gone, not only how the latest attempt ended (B9):
//   - the latest attempt in flight or unknown: in_flight or
//     outcome_unknown;
//   - otherwise one attempt went: succeeded, whatever a later one did (an
//     earlier parked attempt a check settled after the owner's retry);
//   - otherwise an earlier attempt is still unknown: outcome_unknown. Only
//     the owner's retry of a parked attempt starts a new attempt while one
//     is unknown (Retry), so this is a parked attempt whose retry the
//     service then refused or a check proved not done (unclear): the
//     effect may still have gone by it;
//   - otherwise not_applied.
func (en *entry) derive() State {
	switch en.latest().Result {
	case ResultInFlight:
		return InFlight
	case ResultUnknown:
		return OutcomeUnknown
	}
	if en.wentSeq != 0 {
		return Succeeded
	}
	if unclearOf(en.attempts) != 0 {
		return OutcomeUnknown
	}
	return NotApplied
}

// unclearOf returns the first attempt before the latest whose outcome is
// still unknown, when the latest is settled, or 0.
func unclearOf(as []Attempt) int {
	if len(as) == 0 {
		return 0
	}
	if r := as[len(as)-1].Result; r == ResultUnknown || r == ResultInFlight {
		return 0
	}
	for _, a := range as[:len(as)-1] {
		if a.Result == ResultUnknown {
			return a.N
		}
	}
	return 0
}

// unclear returns the parked attempt an outcome_unknown intent waits on
// when its latest attempt, the owner's retry, did not go, or 0 (derive).
// It is unresolved like any outcome_unknown intent, holding back its
// rivals and any intent with its effect (duplicateOf), and it is offered
// as parked (retryable), never resent or redispatched without the owner.
func (en *entry) unclear() int {
	if en.state != OutcomeUnknown {
		return 0
	}
	return unclearOf(en.attempts)
}

// outstanding is the attempt an in_flight or outcome_unknown intent waits
// on: the latest, or for an unclear intent its earlier parked attempt.
// It is nil for any other state.
func (en *entry) outstanding() *Attempt {
	if en.state != InFlight && en.state != OutcomeUnknown {
		return nil
	}
	if n := en.unclear(); n != 0 {
		return en.attempt(n)
	}
	return en.latest()
}

// retryable reports an intent the owner's RETRY may try again (Retry):
// the attempt it waits on is parked, the latest or, for an unclear
// intent, an earlier one.
func (en *entry) retryable() bool {
	return en.state == OutcomeUnknown && en.parked()
}

// parked reports whether the attempt the intent waits on (outstanding) is
// parked (OP-2).
func (en *entry) parked() bool {
	a := en.outstanding()
	return a != nil && a.Parked
}

func (en *entry) attempt(n int) *Attempt {
	if n < 1 || n > len(en.attempts) {
		return nil
	}
	return &en.attempts[n-1]
}

func (en *entry) status() Status {
	in, _ := normalize(en.intent)
	atts := make([]Attempt, len(en.attempts))
	for i, a := range en.attempts {
		a.Cancels = append([]Cancel(nil), a.Cancels...)
		atts[i] = a
	}
	return Status{Intent: in, State: en.state, Permission: en.permission, Attempts: atts, Quality: en.quality}
}

// safeBool runs an executor hook that answers yes or no. A panic is no.
func safeBool(f func() bool) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return f()
}

// keyLifetime is how long exec's service remembers an idempotency key for
// in: what the executor says (KeyLifetimer), or DefaultKeyLifetime when it
// does not say, says zero or less, or panics.
func keyLifetime(exec Executor, in Intent) (life time.Duration) {
	defer func() {
		if recover() != nil || life <= 0 {
			life = DefaultKeyLifetime
		}
	}()
	if kl, ok := exec.(KeyLifetimer); ok {
		return kl.KeyLifetime(in)
	}
	return DefaultKeyLifetime
}

// safeCall runs an executor method. A panic or a result that is not
// evidence becomes unknown: the call may have reached the service.
func safeCall(f func() Outcome) (out Outcome) {
	defer func() {
		if p := recover(); p != nil {
			out = Outcome{Result: ResultUnknown, Evidence: fmt.Sprintf("executor panicked: %v", p)}
		}
	}()
	out = f()
	if out.Result != ResultSucceeded && out.Result != ResultNotApplied {
		out.Result = ResultUnknown
	}
	return out
}
