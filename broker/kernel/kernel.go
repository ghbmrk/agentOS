package kernel

import (
	"errors"
	"fmt"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Kernel refusal codes, beside the key package's.
const (
	CKey       = "key"         // the chain does not verify
	CUngranted = "not-granted" // the passkey never granted the key's root or first link into the log
	CGrantHeld = "grant-held"  // the grant is still in its hold (D-146)
	CCutOff    = "cut-off"     // a passkey cut off since narrowed the key (key.Narrow)
	CPlan      = "plan"        // the plan is malformed
	CDuplicate = "duplicate"   // the same effect within 24 hours needs a fresh owner key (KRN-8)
	CClerk     = "no-clerk"
	CPool      = "pool"       // the pool is at the owner's reserve until it resets (RES-5)
	CNotHeld   = "not-held"   // no hold on that task
	CExtension = "extension"  // the key cannot extend this hold
	CHeld      = "held"       // the task is held until the owner extends it (LOG-7)
	CBroken    = "log-broken" // a write failed: no spend until the log is reopened (KRN-5)
)

// Admit decides a submitted plan against the state. It is pure: the same state
// and plan give the same answer in the live kernel, a replay and the sim (KRN-1).
// The plan is authorized whole, every step charged against the ones before it.
func Admit(s *State, p Plan, now int64) (key.ID, []key.ID, *key.Refusal) {
	if p.ID == "" || len(p.Steps) == 0 || len(p.Steps) > MaxSteps {
		return key.ID{}, nil, &key.Refusal{Code: CPlan, Detail: "empty, unnamed or over the step limit"}
	}
	v, err := VerifyPlan(p, s.owners(p.Key))
	if err != nil {
		return key.ID{}, nil, &key.Refusal{Code: CKey, Detail: err.Error()}
	}
	if r := Live(s, v, now); r != nil {
		return key.ID{}, nil, r
	}
	if r := OneOff(s, s.owners(p.Key), s.Anchors, p, now); r != nil {
		return key.ID{}, nil, r
	}
	if t := v.Limits.Task; t != "" {
		if _, ok := s.Task(t, now); !ok {
			return key.ID{}, nil, &key.Refusal{Code: CTask, Detail: "the key's task is not live"}
		}
	}
	ov := overlay{base: s.Ledger(), extra: map[key.ID][]key.Use{}}
	ctx := key.Context{Now: now, Changes: &s.Changes, Ledger: ov}
	fresh := map[string]bool{}
	for i := range p.Steps {
		st := p.Step(i)
		if !key.Valid(st.Verb) {
			return key.ID{}, nil, &key.Refusal{Code: CPlan, Detail: "unknown verb " + string(st.Verb)}
		}
		if r := v.Authorize(st, ctx); r != nil {
			return key.ID{}, nil, r
		}
		if c, _ := key.ClassOf(st.Verb); c.Irreversible() {
			fp := Fingerprint(st)
			if fresh[fp] || repeats(s, v.Root(), st, p.ID, now) {
				return key.ID{}, nil, &key.Refusal{Code: CDuplicate, Detail: string(st.Verb)}
			}
			fresh[fp] = true
		}
		for _, id := range v.Scopes() {
			ov.extra[id] = append(ov.extra[id], key.Use{At: now, Amount: st.Amount, Recipient: st.Recipient, Task: st.Task})
		}
	}
	return v.Root(), v.Scopes(), nil
}

type overlay struct {
	base  key.Ledger
	extra map[key.ID][]key.Use
}

func (o overlay) Uses(id key.ID) []key.Use {
	b := o.base.Uses(id)
	return append(b[:len(b):len(b)], o.extra[id]...)
}

// repeats reports whether the exact effect completed under this root within a
// day, or is unreconciled in another plan, cancelled or not: a cancel never
// settles an effect that may have happened (KRN-8).
func repeats(s *State, root key.ID, st key.Step, self string, now int64) bool {
	fp := Fingerprint(st)
	if at, ok := s.recent[root][fp]; ok && at > now-key.DayMS {
		return true
	}
	for _, id := range s.Order {
		p := s.Plans[id]
		if id == self || p.Root != root {
			continue
		}
		for i, ss := range p.Steps {
			switch ss.Phase {
			case PInflight, PUnknown, PParked, PRedo, PUnsent:
				if Fingerprint(p.Plan.Step(i)) == fp {
					return true
				}
			}
		}
	}
	return false
}

// Act kinds.
const (
	ActNone     = ""
	ActHold     = "hold"
	ActDispatch = "dispatch"
	ActProbe    = "probe"
	ActCancel   = "cancel"
)

// Act is what a plan needs next.
type Act struct {
	Kind    string
	Plan    string
	Index   int
	Novel   bool
	Attempt int
	Refusal *key.Refusal
	WakeAt  int64 // when ActNone is waiting on a clock: the earliest time to look again
}

// Next is the kernel's whole scheduling rule, pure over the state: re-authorize
// the plan's current step, hold it if irreversible, dispatch it, or probe an
// unknown result (KRN-5, KRN-8).
func Next(s *State, id string, now int64) Act {
	p := s.Plans[id]
	if p == nil || len(p.Steps) == 0 {
		return Act{}
	}
	i := p.Next
	st, sp := p.Steps[i], p.Plan.Step(i)
	a := Act{Plan: id, Index: i}
	if p.Status != SActive && st.Phase != PUnknown {
		return Act{} // a plan that ended still reconciles an unknown result, and nothing else
	}
	switch st.Phase {
	case PUnknown:
		if now < st.NextProbe {
			a.WakeAt = st.NextProbe
			return a
		}
		a.Kind = ActProbe
		return a
	case PUnsent:
		if now < st.NextProbe {
			a.WakeAt = st.NextProbe
			return a
		}
	case PQueued, PHeld, PRedo:
	default:
		return a
	}
	v, err := VerifyPlan(p.Plan, s.owners(p.Plan.Key))
	if err != nil {
		a.Kind, a.Refusal = ActCancel, &key.Refusal{Code: CKey, Detail: err.Error()}
		return a
	}
	led := s.Ledger()
	if st.Attempt > 0 {
		led = s.LedgerBefore(st.DispatchSeq) // a redo is not charged twice
	}
	if r := v.Authorize(sp, key.Context{Now: now, Changes: &s.Changes, Ledger: led}); r != nil {
		if r.Code == key.RPaused {
			return a // waits for key.resumed
		}
		a.Kind, a.Refusal = ActCancel, r
		return a
	}
	class, _ := key.ClassOf(sp.Verb)
	if class.Irreversible() && st.Attempt == 0 && repeats(s, p.Root, sp, id, now) {
		a.Kind, a.Refusal = ActCancel, &key.Refusal{Code: CDuplicate, Detail: string(sp.Verb)}
		return a
	}
	if class.Irreversible() && st.Phase == PQueued && max(v.Limits.Window(false), v.Limits.Window(true)) > 0 {
		a.Kind, a.Novel = ActHold, s.seen[p.Root][Shape(sp)] <= 0
		return a
	}
	if st.Phase == PHeld {
		if due := v.Limits.Due(st.HeldAt, st.Novel); now < due {
			a.WakeAt = due
			return a
		}
	}
	a.Kind, a.Attempt = ActDispatch, st.Attempt+1
	return a
}

// Request names the step a clerk runs: the signed plan and which step of it,
// so the clerk checks the holder's signature itself (CLK-2). It carries
// nothing else. The clerk reads the time from its own clock and the dispatch
// and hold from the log (View.Dispatched), so no field of a request can claim
// a dispatch, a hold or an hour the log and the clerk do not see.
type Request struct {
	Plan  Plan
	Index int
}

// Step is the step the clerk runs, derived from the signed plan. Out of range
// it is the zero step, which names no clerk and so is refused.
func (r Request) Step() key.Step {
	if r.Index < 0 || r.Index >= len(r.Plan.Steps) {
		return key.Step{}
	}
	return r.Plan.Step(r.Index)
}

// Idem is the step's idempotency key (KRN-8).
func (r Request) Idem() string { return Idem(r.Plan.ID, r.Index) }

// Result is a clerk's answer. Outcome is ok, failed or unknown.
type Result struct {
	Outcome, Detail string
	// Covered is the STATUS line of a submit a task approval covered, in
	// the clerk's fixed wording (CLK-3): "Sent on <site>: <label>, <time>".
	Covered string
}

// Dispatch is what the log says of a step in flight: its first dispatch entry
// and its hold, if any.
type Dispatch struct {
	Seq    uint64 // the first dispatch: the key's uses before it are its budget
	Held   bool
	HeldAt int64
	Novel  bool
}

// View is the read-only part of the state a clerk checks against (CLK-2).
type View interface {
	Granted(id key.ID) (from int64, ok bool)
	Enrollments() ([]key.Enrollment, []key.PublicKey)
	ChangesView() *key.Changes
	LedgerBefore(seq uint64) key.Ledger
	// Dispatched answers only for a request the log has in flight now.
	Dispatched(r Request) (Dispatch, bool)
	// OneOffLine is the most a one-off under root may spend alone (OneOff).
	OneOffLine(root key.ID, now int64) int64
	// Task answers only while the task is live at now.
	Task(id string, now int64) (Task, bool)
}

// Live refuses a key unless its grants, its root and its first link, are in
// the log and past their hold at now (D-146). Keys below the first link are
// narrowings, the clerk's own or a passkey's (key.Narrow), and need no grant;
// a passkey's stands only while that passkey is not cut off.
func Live(v View, ver *key.Verified, now int64) *key.Refusal {
	_, cut := v.Enrollments()
	for _, p := range ver.Narrowers {
		if key.In(cut, p) {
			return &key.Refusal{Code: CCutOff, Detail: "narrowed by a cut-off passkey"}
		}
	}
	for _, id := range ver.IDs[:min(2, len(ver.IDs))] {
		from, ok := v.Granted(id)
		if !ok {
			return &key.Refusal{Code: CUngranted, Detail: id.String()}
		}
		if now < from {
			return &key.Refusal{Code: CGrantHeld, Detail: fmt.Sprintf("live at %d", from)}
		}
	}
	return nil
}

// Clerk is the only exit. Do runs a step at most once per idempotency key
// after its own check of the key. Probe reports done, notdone or unknown
// without acting.
type Clerk interface {
	Do(r Request, v View) Result
	Probe(r Request, v View) Result // Outcome done, notdone or unknown; Covered on a done covered submit
}

// Kernel appends to the log, folds the entry into the state, and runs the
// clerks. Everything it decides comes from Admit and Next.
type Kernel struct {
	log    *Log
	s      *State
	clerks map[string]Clerk
	// asked is the steps whose clerk call Calls handed out and Answer has
	// not had back, so a second Calls does not hand them out again. It is
	// not state: a restart marks the dispatches unknown (Boot) and probes
	// them again.
	asked map[stepRef]bool
	// The subject-key table and content stores, from OpenContent (erase.go).
	keys   Keys
	stores map[string]ContentStore
	retry  map[eraseRef]backoff // deletes and re-seals backing off (erase.go)
	// The older backups, from OpenBackups, and those whose re-seal Reseals
	// handed out and Resealed has not had back (erase.go).
	backups   Backups
	resealing map[string]bool
}

var ErrDuplicatePlan = errors.New("kernel: plan id already used")

// Boot opens a kernel over a log: replay it, decide any plan that was
// submitted but not decided, and mark every step that was in flight unknown,
// to be probed (KRN-8).
func Boot(l *Log, anchors []key.PublicKey, clerks map[string]Clerk, now int64) (*Kernel, error) {
	s, err := Replay(anchors, l.Entries())
	if err != nil {
		return nil, err
	}
	k := &Kernel{log: l, s: s, clerks: clerks, asked: map[stepRef]bool{}}
	for _, id := range append([]string(nil), s.Order...) {
		if s.Plans[id].Status == SPending {
			if err := k.decide(now, id); err != nil {
				return nil, err
			}
		}
	}
	for _, id := range append([]string(nil), s.Order...) {
		p := s.Plans[id]
		if len(p.Steps) > 0 && p.Steps[p.Next].Phase == PInflight {
			if err := k.result(now, id, p.Next, "unknown", "restart"); err != nil {
				return nil, err
			}
		}
	}
	return k, nil
}

func (k *Kernel) State() *State { return k.s }
func (k *Kernel) Log() *Log     { return k.log }

// emit logs first, then folds: a failed write leaves the state as it was.
func (k *Kernel) emit(now int64, typ string, body any) (Entry, error) {
	e, err := k.log.Append(now, typ, schema[typ], body)
	if err != nil {
		return e, err
	}
	if err := k.s.Apply(e); err != nil {
		return e, fmt.Errorf("kernel: log entry does not fold: %w", err)
	}
	return e, nil
}

// Owner actions. The owner channel authenticates them; the kernel only records.

func (k *Kernel) Issue(now int64, cos []key.Cosign, keys ...key.Key) error {
	if _, err := k.s.grants(keys, cos, now); err != nil {
		return err
	}
	return k.owner(now, TKeyIssued, grantBatch{keys, cos})
}

// SetLine sets the owner's line for a big change. Lowering it narrows; a raise
// is itself big, so it needs two passkeys, one an anchor, over
// LineHash(State.LineChanges(), percent).
func (k *Kernel) SetLine(now, percent int64, cos ...key.Cosign) error {
	b := lineSet{percent, cos}
	if err := k.s.lineOK(b); err != nil {
		return err
	}
	return k.owner(now, TLine, b)
}

// ErrNotEnrolled refuses an enrollment no anchor signed.
var ErrNotEnrolled = errors.New("kernel: enrollment not signed by an anchor")

// Enroll adds a passkey, such as a new phone, to the owner's set (D-146). An
// anchor signs it, so it is live at once; it is a widening, so it anchors.
func (k *Kernel) Enroll(now int64, e key.Enrollment) error {
	if !key.In(key.Passkeys(k.s.Anchors, []key.Enrollment{e}, k.s.Unenrolled), e.Passkey) {
		return ErrNotEnrolled
	}
	return k.owner(now, TEnrolled, enrolled{e})
}

// ErrNotUnenrolled refuses a cut-off no hardware key signed (KEY-4, #3209).
var ErrNotUnenrolled = errors.New("kernel: cut-off not signed by an anchor")

// Unenroll cuts a passkey off for good, such as a lost phone's, on an
// anchor's signature over key.UnenrollMsg; a phone passkey's, or none, logs
// nothing. Keys derived from its grants in the log stand until they lapse;
// it signs no new grant and no plan under a bare root.
func (k *Kernel) Unenroll(now int64, u key.Unenrollment) error {
	if key.In(k.s.Anchors, u.Passkey) {
		return ErrAnchor
	}
	if !u.Signed(k.s.Anchors) {
		return ErrNotUnenrolled
	}
	return k.owner(now, TUnenrolled, unenrolled{u})
}

// ErrAnchor refuses cutting off a hardware key: an anchor is replaced only
// by recovery (REC-3), never by an owner action one forged message could
// make (#2670 item 3).
var ErrAnchor = errors.New("kernel: an anchor is cut off only by recovery")

// owned verifies ky as a chain from the owner and that its grants are live.
// It is for keys the log already vouches for: a plan's key was held when the
// plan was admitted (VerifyPlan), and an extension comes over the owner
// channel. The result can be charged but never authorizes a step.
func (k *Kernel) owned(now int64, ky key.Key) (*key.Verified, *key.Refusal) {
	v, err := key.Chain(ky, k.s.owners(ky))
	if err != nil {
		return nil, &key.Refusal{Code: CKey, Detail: err.Error()}
	}
	if r := Live(k.s, v, now); r != nil {
		return nil, r
	}
	return v, nil
}

// funding is the key a plan's model calls are charged to: the latest
// extension the owner's envelope gave it, else the key it cites. Callers name
// the plan, never a key or a task, so renaming cannot escape a cap or a hold
// (LOG-7). The task is the plan, as it is for a plan's own steps.
func (k *Kernel) funding(now int64, plan string) (*PlanState, *key.Verified, *key.Refusal) {
	ps := k.s.Plans[plan]
	if ps == nil {
		return nil, nil, &key.Refusal{Code: CPlan, Detail: "unknown plan"}
	}
	if ps.Status == SRejected {
		return nil, nil, &key.Refusal{Code: CPlan, Detail: "plan is rejected"}
	}
	ky := ps.Plan.Key
	if e, ok := k.s.Extended[plan]; ok {
		ky = e
	}
	v, r := k.owned(now, ky)
	return ps, v, r
}

// citedLive refuses once the key the plan cites is paused, revoked or expired,
// or a stop is in force, whatever extension now funds the plan: an owner who
// pauses a key stops its plan's spend (KEY-6).
func (k *Kernel) citedLive(now int64, ps *PlanState) *key.Refusal {
	cited, r := k.owned(now, ps.Plan.Key)
	if r != nil {
		return r
	}
	return cited.Live(key.Context{Now: now, Changes: &k.s.Changes, Ledger: k.s.Ledger()})
}

// Admitted is a metered call's admission: the worst case it may spend,
// reserved against the plan's key in the log until Meter settles it.
type Admitted struct {
	Plan string `json:"plan"`
	Seq  uint64 `json:"seq"` // the reservation entry
}

// AdmitSpend checks that the plan's key may spend amount more under its spend
// caps, that the plan is active and that it is not held, and reserves amount:
// the check a clerk makes before a metered call (LOG-7). The reservation
// counts against every cap until Meter settles it, so calls admitted at once,
// by one clerk or several, never share the same remaining budget (#2613 item
// 1). One that is never settled stays charged at its worst case.
func (k *Kernel) AdmitSpend(now int64, plan string, amount int64) (Admitted, *key.Refusal) {
	if k.log.broken {
		// A call admitted now could not be metered, and may follow a
		// widening whose anchor failed (KRN-5).
		return Admitted{}, &key.Refusal{Code: CBroken, Detail: ErrBroken.Error()}
	}
	ps, v, r := k.funding(now, plan)
	if r != nil {
		return Admitted{}, r
	}
	if r := k.citedLive(now, ps); r != nil {
		return Admitted{}, r
	}
	if ps.Status != SActive {
		return Admitted{}, &key.Refusal{Code: CPlan, Detail: "plan is " + ps.Status}
	}
	if h, held := k.s.SpendHeld[plan]; held {
		return Admitted{}, &key.Refusal{Code: CHeld, Detail: h.Code}
	}
	task := ps.Plan.Task()
	if r := v.Spend(task, amount, key.Context{Now: now, Changes: &k.s.Changes, Ledger: k.s.Ledger()}); r != nil {
		settled := key.Context{Now: now, Changes: &k.s.Changes, Ledger: ledger{s: k.s, settled: true}}
		sr := v.Spend(task, amount, settled)
		if sr != nil {
			// The cap settled usage alone exhausts, which is the one a hold
			// names, even when open admissions push another over first.
			return Admitted{}, sr
		}
		if r.Code == key.RSpendTask || r.Code == key.RSpendDay {
			// Only calls still in flight fill the cap: this one waits for
			// them, and nothing holds the plan.
			return Admitted{}, &key.Refusal{Code: CInFlight, Detail: r.Code}
		}
		return Admitted{}, r
	}
	e, err := k.emit(now, TSpendReserved, spendReserved{v.Root(), v.Scopes(), plan, amount})
	if err != nil {
		return Admitted{}, &key.Refusal{Code: CBroken, Detail: err.Error()}
	}
	return Admitted{plan, e.Seq}, nil
}

// CInFlight refuses a metered call whose worst case fits the caps once the
// calls still in flight settle: the caller may ask again later, and it never
// holds the plan.
const CInFlight = "in-flight"

// ErrNotAdmitted refuses a Meter that cites no open admission.
var ErrNotAdmitted = errors.New("kernel: usage is metered against its own open admission")

// Meter settles admission a with the usage the clerk metered: amount replaces
// the reserved worst case, charged to the key the call was admitted under.
// Usage that happened is always recorded, even past a cap or after the plan
// ended or its key was revoked, so the next admission sees it; a negative
// amount is refused, since spend never refunds. source says whose count
// amount is: the provider's, the clerk's own or the worst case admitted
// (LOG-7).
func (k *Kernel) Meter(now int64, a Admitted, route string, amount int64, source string) error {
	if amount < 0 {
		return errors.New("kernel: metered usage is never negative")
	}
	rs := k.s.reserved[a.Seq]
	if rs == nil || rs.Task != a.Plan {
		return ErrNotAdmitted
	}
	_, err := k.emit(now, TModelUsed, modelUsed{rs.Root, rs.Scopes, a.Plan, route, amount, source, a.Seq})
	return err
}

// Hold stops a plan's spend after rf, the refusal of one of its spend caps,
// used up or too small for the call (MIG-4-spend-b1). It stays held until
// the owner extends it (LOG-7).
func (k *Kernel) Hold(now int64, plan string, rf *key.Refusal) error {
	if rf == nil || (rf.Code != key.RSpendTask && rf.Code != key.RSpendDay) {
		return errors.New("kernel: only a refused spend cap holds a plan")
	}
	ps, v, r := k.funding(now, plan)
	if r != nil {
		return r
	}
	// The cited key was verified when its plan was admitted; its root is all
	// the hold names.
	_, err := k.emit(now, TSpendHeld, spendHeld{plan, rf.Code, rf.Detail, rootOf(ps.Plan.Key), v.ID()})
	return err
}

// Extend releases a held plan under ext, a narrowing derivation of the owner's
// spend envelope (KEY-4). ext must not sit under the root of the key the plan
// cites, nor under the key that was funding it when it was held, so a held key
// cannot release itself, directly or through an earlier extension; it must
// carry a per-task cap in its chain and have room left. The envelope's ceilings,
// charged through the shared chain prefix, bound all extensions together
// (LOG-7). Later calls of the plan are charged to ext.
func (k *Kernel) Extend(now int64, ext key.Key, plan string) error {
	h, ok := k.s.SpendHeld[plan]
	if !ok {
		return &key.Refusal{Code: CNotHeld, Detail: plan}
	}
	if r := k.citedLive(now, k.s.Plans[plan]); r != nil {
		return r
	}
	v, r := k.owned(now, ext)
	if r != nil {
		return r
	}
	if v.Root() == h.Root {
		return &key.Refusal{Code: CExtension, Detail: "a held key cannot release itself"}
	}
	for _, id := range v.IDs {
		if id == h.Funding {
			return &key.Refusal{Code: CExtension, Detail: "a held key cannot release itself"}
		}
	}
	bounded := false
	for _, c := range v.Limits.Caps {
		bounded = bounded || c.Kind == key.KSpendTask
	}
	if !bounded {
		return &key.Refusal{Code: CExtension, Detail: "no per-task cap"}
	}
	if r := v.Spend(k.s.Plans[plan].Plan.Task(), 1, key.Context{Now: now, Changes: &k.s.Changes, Ledger: k.s.Ledger()}); r != nil {
		return r
	}
	return k.owner(now, TSpendExtend, spendExtended{plan, ext})
}

// resetIfDue logs the reopening of a pool at its reserve once the reset time
// the provider gave has passed, so a restart that loses it closes the pool
// again (RES-5, KRN-7).
func (k *Kernel) resetIfDue(now int64, pool string) error {
	if !k.s.PoolDue(now, pool) {
		return nil
	}
	_, err := k.emit(now, TPoolReset, poolReset{pool})
	return err
}

// ReadPool records the provider's figure for a pool: used and the reset time
// (RES-5). A pool at the owner's reserve reopens only at its reset time, never
// on a reading, so a reading can only narrow. A reset time that is missing or
// already past is replaced by the pool's declared window from now, so a full
// pool always has a way back.
func (k *Kernel) ReadPool(now int64, pool string, used, resetAt int64) error {
	if used < 0 || used > PoolFull {
		return errors.New("kernel: utilization is a share of the pool")
	}
	if resetAt <= now {
		resetAt = now + PoolWindowMS
	}
	if err := k.resetIfDue(now, pool); err != nil {
		return err
	}
	if !k.s.PoolOpen(pool) && used+k.s.Pools[pool].Reserve < PoolFull {
		return errors.New("kernel: a pool at the reserve reopens at its reset time, not on a reading")
	}
	_, err := k.emit(now, TPoolRead, poolRead{pool, used, resetAt})
	return err
}

// Reserve sets the share of a pool kept for the owner. Raising narrows, so a
// text is enough; lowering widens, so it is a widening entry (KEY-4, KEY-6).
func (k *Kernel) Reserve(now int64, pool string, reserve int64) error {
	if reserve < 0 || reserve > PoolFull {
		return errors.New("kernel: a reserve is a share of the pool")
	}
	typ := TReserveUp
	if reserve < k.s.Pools[pool].Reserve {
		typ = TReserveDown
	}
	return k.owner(now, typ, poolReserve{pool, reserve})
}

// AdmitPool refuses work on a pool at the owner's reserve until it resets.
// Past the reset time the provider gave, the reopening is logged as a widening.
func (k *Kernel) AdmitPool(now int64, pool string) *key.Refusal {
	if k.log.broken {
		// The pool may have been reopened by a widening whose anchor failed
		// (KRN-5, #2613 item 13).
		return &key.Refusal{Code: CBroken, Detail: ErrBroken.Error()}
	}
	if err := k.resetIfDue(now, pool); err != nil {
		return &key.Refusal{Code: CPool, Detail: pool + ": " + err.Error()}
	}
	if k.s.PoolOpen(pool) {
		return nil
	}
	return &key.Refusal{Code: CPool, Detail: pool}
}

func (k *Kernel) Revoke(now int64, id key.ID) error { return k.owner(now, TKeyRevoked, keyID{id}) }
func (k *Kernel) Pause(now int64, id key.ID) error  { return k.owner(now, TKeyPaused, keyID{id}) }
func (k *Kernel) Unpause(now int64, id key.ID) error {
	return k.owner(now, TKeyResumed, keyID{id})
}
func (k *Kernel) Stop(now int64) error { return k.owner(now, TStop, struct{}{}) }

// ErrStaleResume refuses a RESUME sent before a STOP the kernel has since
// logged: an owner told that STOP holds must not see it lifted (#3078).
var ErrStaleResume = errors.New("kernel: a STOP was logged after this RESUME was sent")

// Resume lifts the STOP whose count it names (State.Stops), and only that
// one: a RESUME that waited behind a later STOP is refused, unlogged.
func (k *Kernel) Resume(now int64, stops uint64) error {
	if stops != k.s.Stops {
		return ErrStaleResume
	}
	return k.owner(now, TResume, struct{}{})
}

// owner records an owner action and anchors the head at once, so a widening
// the owner confirmed survives a restart (KRN-7, LOG-2). When the anchor
// fails after a widening, the entry is already folded into live state, so the
// log is marked broken: nothing builds on it until Open drops it. A narrowing
// (Revoke, Pause, Stop) stays in force and the log stays usable, since Open
// keeps it either way.
func (k *Kernel) owner(now int64, typ string, body any) error {
	if _, err := k.emit(now, typ, body); err != nil {
		return err
	}
	err := k.log.Anchor()
	if err != nil && Widening(typ) {
		k.log.broken = true
	}
	return err
}

// Cancel ends an active plan at the owner's word.
func (k *Kernel) Cancel(now int64, plan string) error {
	_, err := k.emit(now, TPlanCancel, planCancel{Plan: plan, Code: "owner"})
	return err
}

// Undo marks a done step as undone, so its shape counts as new again. The
// effect itself is undone by the owner through the clerk's own undo (KEY-8).
func (k *Kernel) Undo(now int64, plan string, index int) error {
	_, err := k.emit(now, TStepUndone, stepRef{plan, index})
	return err
}

// ErrNotParked refuses a RETRY of a step that is not parked in a live plan.
var ErrNotParked = errors.New("kernel: no parked step of a live plan there to retry")

// ErrRetryRefused refuses a RETRY whose redo the key's checks would refuse
// now (a STOP, a revoke, an expiry, a limit); the step stays parked.
var ErrRetryRefused = errors.New("kernel: the step cannot be sent again now")

// ErrRetryMoved refuses a RETRY asked about an earlier dispatch attempt: the
// step was sent again since, so the owner's approval was not given for this
// send (CH-10).
var ErrRetryMoved = errors.New("kernel: the step was retried since that ask")

// Retry is the owner's RETRY of a parked step (KRN-8, CH-11): the owner
// accepts that its effect may happen twice. The step is sent again under its
// own idempotency key and only after the same checks as any dispatch. Like
// every widening it anchors before it counts. attempt is the dispatch
// attempt the owner was asked about (Unsettled.Attempt); a RETRY of a step
// sent again since is refused.
func (k *Kernel) Retry(now int64, plan string, index, attempt int) error {
	p, st := k.s.step(stepRef{plan, index})
	if st == nil || !retryable(p, st) {
		return ErrNotParked
	}
	if st.Attempt != attempt {
		return ErrRetryMoved
	}
	// A redo that Next would refuse now (a STOP, a revoke, an expiry, a
	// limit) would cancel the plan: refuse the RETRY instead and leave the
	// step parked. A pause only delays the redo until the key resumes.
	if r := sendCheck(k.s, p, st, index, now); r != nil && r.Code != key.RPaused {
		return fmt.Errorf("%w: %s: %s", ErrRetryRefused, r.Code, r.Detail)
	}
	if c := p.Plan.Steps[index].Clerk; k.clerks[c] == nil {
		// The redo could reach no clerk and would cancel the plan.
		return fmt.Errorf("%w: %s: %s", ErrRetryRefused, CClerk, c)
	}
	return k.owner(now, TStepRetried, stepRef{plan, index})
}

// Submit logs a plan and decides it at once.
func (k *Kernel) Submit(now int64, p Plan) error {
	if k.s.Plans[p.ID] != nil {
		return ErrDuplicatePlan
	}
	if _, err := k.emit(now, TPlanSubmit, p); err != nil {
		return err
	}
	return k.decide(now, p.ID)
}

func (k *Kernel) decide(now int64, id string) error {
	p := k.s.Plans[id]
	root, scopes, r := Admit(k.s, p.Plan, now)
	if r != nil {
		_, err := k.emit(now, TPlanRejected, planRejected{Plan: id, Cause: p.Seq, Code: r.Code, Detail: r.Detail})
		return err
	}
	_, err := k.emit(now, TPlanAccepted, planAccepted{Plan: id, Cause: p.Seq, Root: root, Scopes: scopes})
	return err
}

func (k *Kernel) result(now int64, id string, i int, outcome, detail string) error {
	return k.answer(now, id, i, Result{Outcome: outcome, Detail: detail})
}

func (k *Kernel) answer(now int64, id string, i int, res Result) error {
	if !shown(res.Covered) { // bounded before it is logged, not only when folded
		res.Covered = ""
	}
	_, err := k.emit(now, TStepResult, stepResult{stepRef{id, i}, Idem(id, i), res.Outcome, res.Detail, res.Covered})
	return err
}

// Call is one clerk call the kernel wants made: a step it logged as
// dispatched, or an unknown result to probe. The kernel's state is not held
// while it runs, so STOP, a revoke or STATUS never waits on a clerk (KRN-7).
type Call struct {
	Kind  string // ActDispatch or ActProbe
	Clerk string
	Req   Request
}

// Calls runs every active plan as far as now allows without calling a clerk:
// it logs holds, cancels and dispatches, and returns the calls now due, each
// once until Answer has its answer. A step whose clerk the kernel does not
// have fails here.
func (k *Kernel) Calls(now int64) ([]Call, error) {
	var out []Call
	for _, id := range append([]string(nil), k.s.Order...) {
		for n := 0; n < 4*MaxSteps; n++ {
			a := Next(k.s, id, now)
			if a.Kind == ActNone || k.asked[stepRef{a.Plan, a.Index}] {
				break
			}
			c, err := k.act(now, a)
			if err != nil {
				return out, err
			}
			if c != nil {
				k.asked[stepRef{a.Plan, a.Index}] = true
				out = append(out, *c)
				break
			}
		}
	}
	return out, nil
}

// Answer logs a clerk's answer to c: for a dispatch its Result, for a probe
// its finding in Outcome (done, notdone, unknown or OUnreached).
func (k *Kernel) Answer(now int64, c Call, res Result) error {
	delete(k.asked, stepRef{c.Req.Plan.ID, c.Req.Index})
	if c.Kind == ActProbe {
		// Only a done step is listed: no other finding's line is logged.
		if res.Outcome != "done" || !shown(res.Covered) {
			res.Covered = ""
		}
		_, err := k.emit(now, TStepProbed, stepProbed{stepRef{c.Req.Plan.ID, c.Req.Index}, res.Outcome, res.Covered})
		return err
	}
	return k.answer(now, c.Req.Plan.ID, c.Req.Index, res)
}

// Send is the last check before c goes to its clerk, made under the same
// lock as the call's view: a dispatch is sent only while its plan is active
// and its key still authorizes the step, so a STOP, revoke, pause or cancel
// logged since Calls stops it (KRN-7). A dispatch that may not be sent is
// answered unsent, since nothing was sent; a refusal other than a pause then
// cancels its plan. A probe is always sent: reconciliation outlives a stop
// (KRN-8).
func (k *Kernel) Send(now int64, c Call) (bool, error) {
	if c.Kind != ActDispatch {
		return true, nil
	}
	ref := stepRef{c.Req.Plan.ID, c.Req.Index}
	p, st := k.s.step(ref)
	if st == nil || st.Phase != PInflight {
		delete(k.asked, ref)
		return false, nil
	}
	r := &key.Refusal{Code: CPlan, Detail: "plan is " + p.Status}
	if p.Status == SActive {
		r = sendCheck(k.s, p, st, c.Req.Index, now)
	}
	if r == nil {
		return true, nil
	}
	if err := k.Answer(now, c, Result{Outcome: OUnsent}); err != nil {
		return false, err
	}
	if p.Status != SActive || r.Code == key.RPaused {
		return false, nil
	}
	_, err := k.emit(now, TPlanCancel, planCancel{Plan: ref.Plan, Code: r.Code, Detail: r.Detail})
	return false, err
}

// sendCheck checks step i of p as Next did before its dispatch, against the
// ledger before that dispatch, so the dispatch's own charge is not counted
// twice. It is pure over the state, so Rederive makes the same check.
func sendCheck(s *State, p *PlanState, st *StepState, i int, now int64) *key.Refusal {
	v, err := VerifyPlan(p.Plan, s.owners(p.Plan.Key))
	if err != nil {
		return &key.Refusal{Code: CKey, Detail: err.Error()}
	}
	return v.Authorize(p.Plan.Step(i), key.Context{Now: now, Changes: &s.Changes, Ledger: s.LedgerBefore(st.DispatchSeq)})
}

// Tick retries the erases not yet confirmed and the backup re-seals due
// (ResealBackups), then runs every active plan as
// far as the clock allows, calling the in-process clerks it was booted with
// as it goes. A step that cannot move
// yet is left for a later Tick.
func (k *Kernel) Tick(now int64) error {
	if k.keys != nil {
		if err := k.confirmErases(now); err != nil {
			return err
		}
		k.ResealBackups(now)
	}
	for n := 0; n < 4*MaxSteps; n++ {
		cs, err := k.Calls(now)
		if err != nil || len(cs) == 0 {
			return err
		}
		for _, c := range cs {
			ok, err := k.Send(now, c)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			cl := k.clerks[c.Clerk]
			var res Result
			if c.Kind == ActProbe {
				res = cl.Probe(c.Req, k.s)
			} else {
				res = cl.Do(c.Req, k.s)
			}
			if err := k.Answer(now, c, res); err != nil {
				return err
			}
		}
	}
	return nil
}

// act logs what a returns from Next, and returns the clerk call it needs, if any.
func (k *Kernel) act(now int64, a Act) (*Call, error) {
	ref := stepRef{a.Plan, a.Index}
	p := k.s.Plans[a.Plan]
	switch a.Kind {
	case ActCancel:
		_, err := k.emit(now, TPlanCancel, planCancel{Plan: a.Plan, Code: a.Refusal.Code, Detail: a.Refusal.Detail})
		return nil, err
	case ActHold:
		_, err := k.emit(now, TStepHeld, stepHeld{ref, 0, a.Novel})
		return nil, err
	}
	sp, st := p.Plan.Step(a.Index), p.Steps[a.Index]
	req := Request{Plan: p.Plan, Index: a.Index}
	_, known := k.clerks[sp.Clerk]
	switch a.Kind {
	case ActDispatch:
		if !known {
			// No clerk can run the step, so nothing is sent or charged: the
			// plan is cancelled before its dispatch is logged.
			_, err := k.emit(now, TPlanCancel, planCancel{Plan: a.Plan, Code: CClerk, Detail: sp.Clerk})
			return nil, err
		}
		if _, err := k.emit(now, TStepDispatch, stepDispatch{ref, a.Attempt, req.Idem(), st.HeldSeq}); err != nil {
			return nil, err
		}
		return &Call{ActDispatch, sp.Clerk, req}, nil
	case ActProbe:
		if known {
			return &Call{ActProbe, sp.Clerk, req}, nil
		}
	}
	return nil, nil
}
