package kernel

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Rederived counts what Rederive did with each entry type: decisions it
// re-derived and found equal, and inputs it folded as given.
type Rederived struct {
	Checked  map[string]int
	Recorded map[string]int
}

// Divergence is the first logged decision the entries before it do not give.
type Divergence struct {
	Seq     uint64
	Type    string
	Logged  string // the entry's type and body
	Derived string // what the kernel derives at that point, or "nothing"
}

func (d *Divergence) Error() string {
	return fmt.Sprintf("rederive: entry %d logged %s; the entries before it give %s", d.Seq, d.Logged, d.Derived)
}

// derived is one entry the kernel would log.
type derived struct {
	typ  string
	body []byte
}

func (d derived) String() string { return d.typ + " " + string(d.body) }

// Rederive folds es from empty and, before each decision in it, derives that
// decision again from the state so far at the entry's own time, with the same
// pure functions the live kernel used (Admit, Next, the send check, PoolDue),
// and compares bytes. Inputs (owner actions, plans, clerk answers and probes,
// metered usage, pool readings) are folded as given: the log is where they
// enter (KRN-1). So a log prefix reproduces every decision in it, and the
// first that differs is returned as a *Divergence. A decision the kernel
// should have logged and did not is not seen: a tick that logs nothing
// leaves no entry.
func Rederive(anchors []key.PublicKey, es []Entry) (Rederived, error) {
	s := NewState(anchors)
	out := Rederived{Checked: map[string]int{}, Recorded: map[string]int{}}
	var refused *derived // the cancel a refused send may log next
	for _, e := range es {
		cands, decision := derive(s, e, refused)
		if decision {
			if !matches(cands, e) {
				d := &Divergence{Seq: e.Seq, Type: e.Type, Logged: derived{e.Type, e.Body}.String(), Derived: "nothing"}
				if len(cands) > 0 {
					d.Derived = cands[0].String()
				}
				return out, d
			}
			out.Checked[e.Type]++
		} else {
			out.Recorded[e.Type]++
		}
		refused = refusedSend(s, e)
		if err := s.Apply(e); err != nil {
			return out, err
		}
	}
	return out, nil
}

func matches(cands []derived, e Entry) bool {
	for _, c := range cands {
		if c.typ == e.Type && bytes.Equal(c.body, e.Body) {
			return true
		}
	}
	return false
}

func entry(typ string, body any) derived {
	b, _ := json.Marshal(body)
	return derived{typ, b}
}

// derive gives the entries the kernel could log in e's place from s at e.At,
// and whether e is a decision at all.
func derive(s *State, e Entry, refused *derived) ([]derived, bool) {
	var ref struct {
		Plan string `json:"plan"`
		Code string `json:"code"`
		Pool string `json:"pool"`
	}
	switch e.Type {
	case TPlanAccepted, TPlanRejected:
		_ = json.Unmarshal(e.Body, &ref)
		return decision(s, ref.Plan, e.At), true
	case TStepHeld, TStepDispatch:
		_ = json.Unmarshal(e.Body, &ref)
		return scheduled(s, ref.Plan, e.At), true
	case TPlanCancel:
		_ = json.Unmarshal(e.Body, &ref)
		if ref.Code == "owner" {
			return nil, false // Cancel: the owner's
		}
		cands := scheduled(s, ref.Plan, e.At)
		if refused != nil {
			cands = append(cands, *refused)
		}
		return cands, true
	case TPoolReset:
		_ = json.Unmarshal(e.Body, &ref)
		if s.PoolDue(e.At, ref.Pool) {
			return []derived{entry(TPoolReset, poolReset{ref.Pool})}, true
		}
		return nil, true
	}
	// A type the kernel adds is a decision with no derivation until it is
	// listed here or derived above, so none is folded unchecked by default.
	return nil, !recorded[e.Type]
}

// recorded is every entry type folded as given. All are inputs but
// model.reserved, AdmitSpend's decision, which hangs on the log's broken
// flag, not on state, so it is not re-derived (#2934).
var recorded = map[string]bool{
	TKeyIssued: true, TKeyRevoked: true, TKeyPaused: true, TKeyResumed: true, TEnrolled: true, TUnenrolled: true,
	TLine: true, TStop: true, TResume: true, TPlanSubmit: true, TStepResult: true, TStepProbed: true,
	TStepUndone: true, TStepRetried: true, TModelUsed: true, TSpendReserved: true, TSpendHeld: true,
	TSpendExtend: true, TPoolRead: true, TReserveUp: true, TReserveDown: true,
	TTaskOpened: true, TTaskApproved: true, TTaskEnded: true, TAnchorsSet: true,
	TSubjectOpened: true, TContentStored: true, TSubjectErased: true, TEraseConfirmed: true,
	TBackupTarget: true, TBackupUntarget: true,
}

// decision is decide's entry for a pending plan.
func decision(s *State, id string, now int64) []derived {
	p := s.Plans[id]
	if p == nil || p.Status != SPending {
		return nil
	}
	root, scopes, r := Admit(s, p.Plan, now)
	if r != nil {
		return []derived{entry(TPlanRejected, planRejected{Plan: id, Cause: p.Seq, Code: r.Code, Detail: r.Detail})}
	}
	return []derived{entry(TPlanAccepted, planAccepted{Plan: id, Cause: p.Seq, Root: root, Scopes: scopes})}
}

// scheduled is act's entry for what Next gives. A dispatch whose clerk the
// kernel was not booted with is cancelled instead; the log does not name
// the booted clerks, so either is a derivation of the same Act.
func scheduled(s *State, id string, now int64) []derived {
	a := Next(s, id, now)
	ref := stepRef{a.Plan, a.Index}
	switch a.Kind {
	case ActCancel:
		return []derived{entry(TPlanCancel, planCancel{Plan: a.Plan, Code: a.Refusal.Code, Detail: a.Refusal.Detail})}
	case ActHold:
		return []derived{entry(TStepHeld, stepHeld{ref, 0, a.Novel})}
	case ActDispatch:
		p := s.Plans[a.Plan]
		return []derived{
			entry(TStepDispatch, stepDispatch{ref, a.Attempt, Idem(a.Plan, a.Index), p.Steps[a.Index].HeldSeq}),
			entry(TPlanCancel, planCancel{Plan: a.Plan, Code: CClerk, Detail: p.Plan.Step(a.Index).Clerk}),
		}
	}
	return nil
}

// refusedSend is the cancel Send logs right after e, when e is the unsent
// answer Send gives a dispatch its send check refuses, judged on the state
// before e. An unsent answer from the transport carries no cancel, so the
// cancel is allowed next, never required.
func refusedSend(s *State, e Entry) *derived {
	if e.Type != TStepResult {
		return nil
	}
	var b stepResult
	if json.Unmarshal(e.Body, &b) != nil || b.Outcome != OUnsent {
		return nil
	}
	p, st := s.step(b.stepRef)
	if st == nil || st.Phase != PInflight || p.Status != SActive {
		return nil
	}
	r := sendCheck(s, p, st, b.Index, e.At)
	if r == nil || r.Code == key.RPaused {
		return nil
	}
	d := entry(TPlanCancel, planCancel{Plan: b.Plan, Code: r.Code, Detail: r.Detail})
	return &d
}
