package journal

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Engine runs intents through their lifecycle on top of a journal. All
// methods are safe for concurrent use. Executors and policies run without
// the engine lock held.
type Engine struct {
	mu      sync.Mutex
	store   Store
	policy  Policy
	redact  Redactor
	execs   map[string]Executor
	now     func() time.Time
	seq     uint64
	intents map[string]*entry
	order   []string
	records []Record
	stopped bool
	// fence maps an account to the intents left unresolved by the last
	// restart. Dispatch on the account waits until it is empty (OP-4).
	fence  map[string]map[string]bool
	broken error
}

type entry struct {
	intent     Intent
	fp         string
	efp        string // effectFingerprint
	state      State
	permission Permission
	attempts   []Attempt
	quality    Quality
	authorized time.Time // when RecAuthorized was journaled
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
		fence:   map[string]map[string]bool{},
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
	for _, id := range e.order {
		en := e.intents[id]
		if en.state != InFlight {
			continue
		}
		n := en.attempts[len(en.attempts)-1].N
		if err := e.commit(Record{Type: RecObserved, ID: id, Attempt: n, Result: ResultUnknown,
			Source: "restart", Evidence: "in flight when the broker stopped"}); err != nil {
			return nil, err
		}
	}
	for _, id := range e.order {
		en := e.intents[id]
		if en.state == OutcomeUnknown {
			if e.fence[en.intent.Account] == nil {
				e.fence[en.intent.Account] = map[string]bool{}
			}
			e.fence[en.intent.Account][id] = true
		}
	}
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
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.broken != nil {
		return Status{}, e.broken
	}
	if en, ok := e.intents[norm.ID]; ok {
		if en.fp != fingerprint(norm) {
			return Status{}, fmt.Errorf("%w: %s", ErrConflict, norm.ID)
		}
		return en.status(), nil
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
	en, err := e.lookup(id)
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
		r = Record{Type: RecDenied, ID: id, Reason: perr.Error()}
	}
	if err := e.commit(r); err != nil {
		return Status{}, err
	}
	return en.status(), nil
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
			err := e.commit(Record{Type: RecRecheckFailed, ID: id, Reason: perr.Error()})
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
	en, err := e.lookup(id)
	if err != nil {
		return nil, nil, err
	}
	if en.state != Authorized && en.state != NotApplied {
		return en, nil, fmt.Errorf("%w: %s is %s", ErrState, id, en.state)
	}
	exempt := narrowing(en.intent)
	if e.stopped && !exempt {
		return en, nil, ErrStopped
	}
	if len(e.fence[en.intent.Account]) > 0 && !exempt {
		return en, nil, fmt.Errorf("%w: %s", ErrUnreconciled, en.intent.Account)
	}
	// The same effect under a new ID while an earlier one may have landed
	// is not a retry the engine can tell apart from a duplicate (OP-2). It
	// stays authorized, held behind the earlier intent (see Waiting).
	if oid := e.duplicateOf(en); oid != "" {
		return en, nil, &HeldError{ID: id, BlockedBy: oid}
	}
	exec, ok := e.execs[en.intent.Executor]
	if !ok {
		return en, nil, fmt.Errorf("%w: %q", ErrNoExecutor, en.intent.Executor)
	}
	return en, exec, nil
}

// duplicateOf returns an unresolved intent with the same effect as en
// under another ID, or "". Called with e.mu held.
func (e *Engine) duplicateOf(en *entry) string {
	for _, oid := range e.order {
		o := e.intents[oid]
		if o != en && o.efp == en.efp && (o.state == OutcomeUnknown || o.state == InFlight) {
			return oid
		}
	}
	return ""
}

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
	for _, id := range e.order {
		en := e.intents[id]
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

// ReconcileReport lists intents reconciliation resolved and those it could
// not.
type ReconcileReport struct {
	Resolved   []string
	Unresolved []string
}

// Reconcile asks each executor for evidence about every outcome_unknown
// attempt. It only reads from services, so it runs even while stopped.
func (e *Engine) Reconcile(ctx context.Context) ReconcileReport {
	e.mu.Lock()
	type job struct {
		in   Intent
		n    int
		exec Executor
	}
	var jobs []job
	for _, id := range e.order {
		en := e.intents[id]
		if en.state == OutcomeUnknown {
			jobs = append(jobs, job{en.intent, en.attempts[len(en.attempts)-1].N, e.execs[en.intent.Executor]})
		}
	}
	e.mu.Unlock()

	var rep ReconcileReport
	for _, j := range jobs {
		out := Outcome{Result: ResultUnknown}
		if j.exec != nil {
			out = safeCall(func() Outcome { return j.exec.Reconcile(ctx, j.in, j.n) })
		}
		if out.Result == ResultUnknown {
			rep.Unresolved = append(rep.Unresolved, j.in.ID)
			continue
		}
		if _, err := e.Resolve(j.in.ID, j.n, out, "reconcile"); err != nil {
			rep.Unresolved = append(rep.Unresolved, j.in.ID)
			continue
		}
		rep.Resolved = append(rep.Resolved, j.in.ID)
	}
	return rep
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
	en, err := e.lookup(id)
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
	for _, id := range e.order {
		en := e.intents[id]
		switch en.state {
		case Authorized, NotApplied:
			if !narrowing(en.intent) {
				rep.Held = append(rep.Held, id)
			}
		case InFlight, OutcomeUnknown:
			rep.Unresolved = append(rep.Unresolved, id)
			jobs = append(jobs, job{en.intent, en.attempts[len(en.attempts)-1].N})
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
	en, err := e.lookup(id)
	if err != nil {
		return Status{}, err
	}
	if err := e.commit(Record{Type: RecQuality, ID: id, Verdict: q.Verdict, Source: q.Source, Evidence: q.Note}); err != nil {
		return Status{}, err
	}
	return en.status(), nil
}

// Get returns one intent's status.
func (e *Engine) Get(id string) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	en, ok := e.intents[id]
	if !ok {
		return Status{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return en.status(), nil
}

// List returns every intent in submission order.
func (e *Engine) List() []Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Status, 0, len(e.order))
	for _, id := range e.order {
		out = append(out, e.intents[id].status())
	}
	return out
}

// AuthorizedSince returns the intents on account with action that were
// authorized at or after since and not later denied by the recheck, oldest
// first. Pre-allowance scope bounds count them (ADP-9): an authorized intent
// holds its place in the bound until the recheck before dispatch refuses it.
func (e *Engine) AuthorizedSince(account, action string, since time.Time) []Intent {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Intent
	for _, id := range e.order {
		en := e.intents[id]
		if en.intent.Account != account || en.intent.Action != action || en.state == Denied || en.authorized.IsZero() {
			continue
		}
		if !en.authorized.Before(since) {
			out = append(out, en.intent)
		}
	}
	return out
}

// Trail returns the journal records, oldest first: one audit trail for
// effects and broker-state changes (OP-5).
func (e *Engine) Trail() []Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Record, len(e.records))
	copy(out, e.records)
	return out
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

func (e *Engine) lookup(id string) (*entry, error) {
	if e.broken != nil {
		return nil, e.broken
	}
	en, ok := e.intents[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return en, nil
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
		if en.state != Authorized && en.state != NotApplied {
			return fmt.Errorf("%s: recheck from %s", r.ID, en.state)
		}
	case RecDispatched:
		if e.stopped && !narrowing(en.intent) {
			return fmt.Errorf("%s: dispatched while stopped", r.ID)
		}
		if en.state != Authorized && en.state != NotApplied {
			return fmt.Errorf("%s: dispatched from %s", r.ID, en.state)
		}
		if r.Attempt != len(en.attempts)+1 {
			return fmt.Errorf("%s: attempt %d, want %d", r.ID, r.Attempt, len(en.attempts)+1)
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
	case RecQuality:
		if r.Verdict != VerdictGood && r.Verdict != VerdictWrong {
			return fmt.Errorf("%s: verdict %q", r.ID, r.Verdict)
		}
	default:
		return fmt.Errorf("unknown record type %q", r.Type)
	}
	return nil
}

// apply moves state forward by one validated record.
func (e *Engine) apply(r Record) {
	e.seq = r.Seq
	e.records = append(e.records, r)
	switch r.Type {
	case RecStop:
		e.stopped = true
		return
	case RecResume:
		e.stopped = false
		return
	case RecEgress:
		return
	case RecSubmitted:
		in := *r.Intent
		e.intents[r.ID] = &entry{intent: in, fp: fingerprint(in), efp: effectFingerprint(in), state: Pending}
		e.order = append(e.order, r.ID)
		return
	}
	en := e.intents[r.ID]
	switch r.Type {
	case RecAuthorized:
		en.state = Authorized
		en.authorized = r.At
		en.permission = Permission{Decision: "allowed", Phase: PhaseAuthorize}
	case RecDenied:
		en.state = Denied
		en.permission = Permission{Decision: "denied", Phase: PhaseAuthorize, Reason: r.Reason}
	case RecRecheckFailed:
		en.state = Denied
		en.permission = Permission{Decision: "denied", Phase: PhaseDispatch, Reason: r.Reason}
	case RecDispatched:
		en.state = InFlight
		en.attempts = append(en.attempts, Attempt{N: r.Attempt, Result: ResultInFlight})
	case RecObserved:
		a := en.attempt(r.Attempt)
		a.Result, a.Source, a.Evidence = r.Result, r.Source, r.Evidence
		if a.N == len(en.attempts) {
			en.state = map[Result]State{ResultSucceeded: Succeeded, ResultNotApplied: NotApplied, ResultUnknown: OutcomeUnknown}[r.Result]
		}
		if r.Result != ResultUnknown {
			if f := e.fence[en.intent.Account]; f != nil {
				delete(f, r.ID)
			}
		}
	case RecCancel:
		a := en.attempt(r.Attempt)
		a.Cancels = append(a.Cancels, Cancel{Accepted: r.Accepted, Detail: r.Evidence})
	case RecQuality:
		en.quality = Quality{Verdict: r.Verdict, Source: r.Source, Note: r.Evidence}
	}
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
