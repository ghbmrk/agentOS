package kernel

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Kernel refusal codes, beside the key package's.
const (
	CKey         = "key"          // the chain does not verify
	CUnknownRoot = "unknown-root" // the root was never issued into the log
	CPlan        = "plan"         // the plan is malformed
	CDuplicate   = "duplicate"    // the same effect within 24 hours needs a fresh owner key (KRN-8)
	CClerk       = "no-clerk"
)

// Admit decides a submitted plan against the state. It is pure: the same state
// and plan give the same answer in the live kernel, a replay and the sim (KRN-1).
// The plan is authorized whole, every step charged against the ones before it.
func Admit(s *State, p Plan, now int64) (key.ID, []key.ID, *key.Refusal) {
	if p.ID == "" || len(p.Steps) == 0 || len(p.Steps) > MaxSteps {
		return key.ID{}, nil, &key.Refusal{Code: CPlan, Detail: "empty, unnamed or over the step limit"}
	}
	v, err := key.Verify(p.Key, s.Owner)
	if err != nil {
		return key.ID{}, nil, &key.Refusal{Code: CKey, Detail: err.Error()}
	}
	if !s.Roots[v.Root()] {
		return key.ID{}, nil, &key.Refusal{Code: CUnknownRoot, Detail: v.Root().String()}
	}
	ov := overlay{base: s.Ledger(), extra: map[key.ID][]key.Use{}}
	ctx := key.Context{Now: now, Changes: &s.Changes, Ledger: ov}
	fresh := map[string]bool{}
	for _, st := range p.Steps {
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
		for _, id := range v.IDs {
			ov.extra[id] = append(ov.extra[id], key.Use{At: now, Amount: st.Amount, Recipient: st.Recipient, Task: st.Task})
		}
	}
	return v.Root(), v.IDs, nil
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
			case PInflight, PUnknown, PParked, PRedo:
				if Fingerprint(p.Plan.Steps[i]) == fp {
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
	st, sp := p.Steps[i], p.Plan.Steps[i]
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
	case PQueued, PHeld, PRedo:
	default:
		return a
	}
	v, err := key.Verify(p.Plan.Key, s.Owner)
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
		if due := st.HeldAt + v.Limits.Window(st.Novel); now < due {
			a.WakeAt = due
			return a
		}
	}
	a.Kind, a.Attempt = ActDispatch, st.Attempt+1
	return a
}

// Request is what a clerk runs and re-checks.
type Request struct {
	Plan        string
	Index       int
	Step        key.Step
	Key         key.Key
	Idem        string
	Attempt     int
	DispatchSeq uint64 // the first dispatch: the clerk counts uses before it
	HeldSeq     uint64 // 0 when the step was not held
	Now         int64
}

// Result is a clerk's answer. Outcome is ok, failed or unknown.
type Result struct{ Outcome, Detail string }

// View is the read-only part of the state a clerk checks against (CLK-2).
type View interface {
	Known(root key.ID) bool
	ChangesView() *key.Changes
	LedgerBefore(seq uint64) key.Ledger
	Held(seq uint64) (HeldInfo, bool)
}

// Clerk is the only exit. Do runs a step at most once per Idem after its own
// check of the key. Probe reports done, notdone or unknown without acting.
type Clerk interface {
	Do(r Request, v View) Result
	Probe(r Request, v View) string
}

// Kernel appends to the log, folds the entry into the state, and runs the
// clerks. Everything it decides comes from Admit and Next.
type Kernel struct {
	log    *Log
	s      *State
	clerks map[string]Clerk
}

var ErrDuplicatePlan = errors.New("kernel: plan id already used")

// Boot opens a kernel over a log: replay it, decide any plan that was
// submitted but not decided, and mark every step that was in flight unknown,
// to be probed (KRN-8).
func Boot(l *Log, owner ed25519.PublicKey, clerks map[string]Clerk, now int64) (*Kernel, error) {
	s, err := Replay(owner, l.Entries())
	if err != nil {
		return nil, err
	}
	k := &Kernel{log: l, s: s, clerks: clerks}
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
	e, err := k.log.Append(now, typ, 1, body)
	if err != nil {
		return e, err
	}
	if err := k.s.Apply(e); err != nil {
		return e, fmt.Errorf("kernel: log entry does not fold: %w", err)
	}
	return e, nil
}

// Owner actions. The owner channel authenticates them; the kernel only records.

func (k *Kernel) Issue(now int64, root key.Key) error {
	if len(root.Links) != 0 {
		return errors.New("kernel: only a root is issued")
	}
	if _, err := key.Verify(root, k.s.Owner); err != nil {
		return err
	}
	_, err := k.emit(now, TKeyIssued, keyIssued{root})
	return err
}

func (k *Kernel) Revoke(now int64, id key.ID) error {
	_, err := k.emit(now, TKeyRevoked, keyID{id})
	return err
}
func (k *Kernel) Pause(now int64, id key.ID) error {
	_, err := k.emit(now, TKeyPaused, keyID{id})
	return err
}
func (k *Kernel) Unpause(now int64, id key.ID) error {
	_, err := k.emit(now, TKeyResumed, keyID{id})
	return err
}
func (k *Kernel) Stop(now int64) error   { _, err := k.emit(now, TStop, struct{}{}); return err }
func (k *Kernel) Resume(now int64) error { _, err := k.emit(now, TResume, struct{}{}); return err }

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
	_, err := k.emit(now, TStepResult, stepResult{stepRef{id, i}, Idem(id, i), outcome, detail})
	return err
}

// Tick runs every active plan as far as the clock allows. A step that cannot
// move yet is left for a later Tick.
func (k *Kernel) Tick(now int64) error {
	for _, id := range append([]string(nil), k.s.Order...) {
		for n := 0; n < 4*MaxSteps; n++ {
			a := Next(k.s, id, now)
			if a.Kind == ActNone {
				break
			}
			if err := k.act(now, a); err != nil {
				return err
			}
		}
	}
	return nil
}

func (k *Kernel) act(now int64, a Act) error {
	ref := stepRef{a.Plan, a.Index}
	p := k.s.Plans[a.Plan]
	switch a.Kind {
	case ActCancel:
		_, err := k.emit(now, TPlanCancel, planCancel{Plan: a.Plan, Code: a.Refusal.Code, Detail: a.Refusal.Detail})
		return err
	case ActHold:
		_, err := k.emit(now, TStepHeld, stepHeld{ref, 0, a.Novel})
		return err
	}
	sp, st := p.Plan.Steps[a.Index], p.Steps[a.Index]
	c := k.clerks[sp.Clerk]
	if c == nil {
		if a.Kind == ActDispatch {
			if _, err := k.emit(now, TStepDispatch, stepDispatch{ref, a.Attempt, Idem(a.Plan, a.Index), st.HeldSeq}); err != nil {
				return err
			}
			return k.result(now, a.Plan, a.Index, "failed", CClerk)
		}
		return nil
	}
	req := Request{Plan: a.Plan, Index: a.Index, Step: sp, Key: p.Plan.Key, Idem: Idem(a.Plan, a.Index),
		Attempt: a.Attempt, DispatchSeq: st.DispatchSeq, HeldSeq: st.HeldSeq, Now: now}
	switch a.Kind {
	case ActDispatch:
		e, err := k.emit(now, TStepDispatch, stepDispatch{ref, a.Attempt, req.Idem, st.HeldSeq})
		if err != nil {
			return err
		}
		if a.Attempt == 1 {
			req.DispatchSeq = e.Seq
		}
		res := c.Do(req, k.s)
		return k.result(now, a.Plan, a.Index, res.Outcome, res.Detail)
	case ActProbe:
		_, err := k.emit(now, TStepProbed, stepProbed{ref, c.Probe(req, k.s)})
		return err
	}
	return nil
}
