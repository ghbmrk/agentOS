package kernel

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Limits on a plan and on reconciliation.
const (
	MaxSteps   = 64
	MaxChecks  = 10     // KRN-8: parked after ten checks
	ProbeEvery = 60_000 // ms between reconciliation checks
)

// Entry types, all version 1. The set is closed (LOG-5).
const (
	TKeyIssued    = "key.issued"
	TKeyRevoked   = "key.revoked"
	TKeyPaused    = "key.paused"
	TKeyResumed   = "key.resumed"
	TStop         = "stop"
	TResume       = "resume"
	TPlanSubmit   = "plan.submitted"
	TPlanAccepted = "plan.accepted"
	TPlanRejected = "plan.rejected"
	TPlanCancel   = "plan.cancelled"
	TStepHeld     = "step.held"
	TStepDispatch = "step.dispatched"
	TStepResult   = "step.result"
	TStepProbed   = "step.probed"
	TStepUndone   = "step.undone"
)

var schema = map[string]int{
	TKeyIssued: 1, TKeyRevoked: 1, TKeyPaused: 1, TKeyResumed: 1, TStop: 1, TResume: 1,
	TPlanSubmit: 1, TPlanAccepted: 1, TPlanRejected: 1, TPlanCancel: 1,
	TStepHeld: 1, TStepDispatch: 1, TStepResult: 1, TStepProbed: 1, TStepUndone: 1,
}

// Known reports whether the log may hold this type at this version.
func Known(typ string, v int) bool { got, ok := schema[typ]; return ok && got == v }

// Widening entries grant power back. Only one that an anchor covers counts
// after a restart (KRN-7).
func Widening(typ string) bool { return typ == TResume || typ == TKeyIssued || typ == TKeyResumed }

// PlanStep is all a planner writes of a step: the verb, the clerk, the
// arguments, and its claims about content and labels. Source, task, recipient
// and amount are the kernel's to derive, so the format has no place for a value
// that looks authoritative and is not (KEY-2, KRN-3).
type PlanStep struct {
	Verb    key.Verb          `json:"verb"`
	Clerk   string            `json:"clerk"`
	Args    map[string]string `json:"args"`
	Content string            `json:"content,omitempty"`
	Labels  []string          `json:"labels,omitempty"`
}

// Plan is a typed list of steps run in order under one key (KRN-5). Sig is
// the key's last holder signing the plan, so holding a key's bytes is not
// using it: a key stripped back toward its root names a holder the submitter
// cannot sign for (KEY-1, KEY-3).
type Plan struct {
	ID    string     `json:"id"`
	Key   key.Key    `json:"key"`
	Steps []PlanStep `json:"steps"`
	Sig   []byte     `json:"sig"`
}

// use is what the holder signs: the id and steps. The key's tip is in the
// signed message already (key.Sign).
func (p Plan) use() []byte {
	b, _ := json.Marshal(struct {
		ID    string     `json:"id"`
		Steps []PlanStep `json:"steps"`
	}{p.ID, p.Steps})
	return b
}

// SignPlan signs p as the holder of p.Key.
func SignPlan(p Plan, holder ed25519.PrivateKey) Plan {
	p.Sig = key.Sign(p.Key, holder, p.use())
	return p
}

// ErrNotText refuses a plan with a string that is not valid UTF-8: JSON
// would encode it as U+FFFD, so two different plans could share a signature.
var ErrNotText = errors.New("kernel: plan text is not valid UTF-8")

// VerifyPlan is the key check for a plan, in the kernel, the clerk and the sim.
func VerifyPlan(p Plan, owner ed25519.PublicKey) (*key.Verified, error) {
	if !p.text() {
		return nil, ErrNotText
	}
	return key.Verify(p.Key, owner, p.use(), p.Sig)
}

// text reports whether every string the holder signs is valid UTF-8.
func (p Plan) text() bool {
	ok := utf8.ValidString(p.ID)
	for _, st := range p.Steps {
		ok = ok && utf8.ValidString(string(st.Verb)) && utf8.ValidString(st.Clerk) && utf8.ValidString(st.Content)
		for n, v := range st.Args {
			ok = ok && utf8.ValidString(n) && utf8.ValidString(v)
		}
		for _, l := range st.Labels {
			ok = ok && utf8.ValidString(l)
		}
	}
	return ok
}

// Step is step i as the key is checked against it and the clerk sees it.
func (p Plan) Step(i int) key.Step { return Normalize(p.ID, p.Steps[i]) }

// Entry bodies.
type (
	keyIssued    struct{ Key key.Key }
	keyID        struct{ ID key.ID }
	planAccepted struct {
		Plan   string   `json:"plan"`
		Cause  uint64   `json:"cause"`
		Root   key.ID   `json:"root"`
		Scopes []key.ID `json:"scopes"`
	}
	planRejected struct {
		Plan   string `json:"plan"`
		Cause  uint64 `json:"cause"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	planCancel struct {
		Plan   string `json:"plan"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	stepRef struct {
		Plan  string `json:"plan"`
		Index int    `json:"index"`
	}
	stepHeld struct {
		stepRef
		ReadyAt int64 `json:"ready_at"`
		Novel   bool  `json:"novel"`
	}
	stepDispatch struct {
		stepRef
		Attempt int    `json:"attempt"`
		Idem    string `json:"idem"`
		HeldSeq uint64 `json:"held_seq"`
	}
	stepResult struct {
		stepRef
		Idem    string `json:"idem"`
		Outcome string `json:"outcome"` // ok, failed, unknown
		Detail  string `json:"detail"`
	}
	stepProbed struct {
		stepRef
		Outcome string `json:"outcome"` // done, notdone, unknown
	}
)

// Step phases.
const (
	PQueued    = "queued"
	PHeld      = "held"
	PInflight  = "inflight"
	PUnknown   = "unknown"
	PRedo      = "redo"
	PParked    = "parked"
	PDone      = "done"
	PFailed    = "failed"
	PCancelled = "cancelled"
)

// Plan statuses.
const (
	SPending   = "pending"
	SActive    = "active"
	SDone      = "done"
	SFailed    = "failed"
	SCancelled = "cancelled"
	SRejected  = "rejected"
)

type StepState struct {
	Phase       string
	HeldSeq     uint64
	HeldAt      int64
	Novel       bool
	Attempt     int
	DispatchSeq uint64
	Checks      int
	NextProbe   int64
	Undone      bool
}

type PlanState struct {
	Plan   Plan
	Seq    uint64 // the submission entry
	Status string
	Root   key.ID
	Scopes []key.ID
	Next   int
	Steps  []StepState
}

// HeldInfo is what a clerk reads to check a step's hold.
type HeldInfo struct {
	Plan  string
	Index int
	At    int64
	Novel bool
}

type usedRec struct {
	Seq uint64
	key.Use
}

// State is the log folded: the only input to Decide besides the event.
type State struct {
	Owner   ed25519.PublicKey
	Seq     uint64
	Stopped bool
	Changes key.Changes
	Roots   map[key.ID]bool
	Plans   map[string]*PlanState
	Order   []string
	uses    map[key.ID][]usedRec
	held    map[uint64]HeldInfo
	seen    map[key.ID]map[string]int   // root -> shape -> completed, not undone
	recent  map[key.ID]map[string]int64 // root -> fingerprint -> time of last completion
}

func NewState(owner ed25519.PublicKey) *State {
	return &State{
		Owner:   owner,
		Changes: key.Changes{Revoked: map[key.ID]bool{}, Paused: map[key.ID]bool{}},
		Roots:   map[key.ID]bool{}, Plans: map[string]*PlanState{},
		uses: map[key.ID][]usedRec{}, held: map[uint64]HeldInfo{},
		seen: map[key.ID]map[string]int{}, recent: map[key.ID]map[string]int64{},
	}
}

// Replay folds a whole log.
func Replay(owner ed25519.PublicKey, es []Entry) (*State, error) {
	s := NewState(owner)
	for _, e := range es {
		if err := s.Apply(e); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Shape is a step's novelty class: a step whose shape has not completed under
// the key's root is novel and gets the longer hold (KEY-8).
func Shape(s key.Step) string {
	labels := append([]string(nil), s.Labels...)
	sort.Strings(labels)
	return strings.Join([]string{string(s.Verb), s.Clerk, s.Recipient, s.Content, strings.Join(labels, ",")}, "|")
}

// Normalize is the one place a submitted step becomes the step the key is
// checked against. The planner writes only arguments, and none of them counts
// as owner or clerk sourced; the task is the plan, the recipient is the verb's object
// argument and the amount is the "amount" argument in its one canonical
// spelling, any other (010, +10) unreadable and so negative, which Authorize
// refuses; one spelling per number keeps the duplicate fingerprint exact. The kernel, the clerk and a replay all see
// this step (KEY-2, KRN-3). Content and labels stay the planner's claims; a
// clerk with facts checks them (CLK-2).
func Normalize(plan string, s PlanStep) key.Step {
	args := make(map[string]key.Arg, len(s.Args))
	for n, v := range s.Args {
		args[n] = key.Arg{Value: v, Source: key.SrcPlanner}
	}
	out := key.Step{Verb: s.Verb, Clerk: s.Clerk, Args: args, Content: s.Content,
		Labels: append([]string(nil), s.Labels...), Task: plan, Recipient: s.Args[key.RecipientArg(s.Verb)]}
	if v, ok := s.Args[key.ArgAmount]; ok {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 || strconv.FormatInt(n, 10) != v {
			n = -1
		}
		out.Amount = n
	}
	return out
}

// Fingerprint names an exact effect: the same one within 24 hours needs a
// fresh owner key (KRN-8). Every field is length-prefixed, so no two different
// argument sets share one.
func Fingerprint(s key.Step) string {
	field := func(x string) string { return strconv.Itoa(len(x)) + ":" + x }
	var kv []string
	for n, a := range s.Args {
		kv = append(kv, field(n)+field(a.Value))
	}
	sort.Strings(kv)
	return field(string(s.Verb)) + field(s.Clerk) + strings.Join(kv, "")
}

// Idem is a step's idempotency key; the clerk runs it at most once (KRN-8).
func Idem(plan string, index int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("agentos.idem.v1\x00%s\x00%d", plan, index)))
	return hex.EncodeToString(h[:])
}

type ledger struct {
	s      *State
	before uint64 // 0: every use
}

func (l ledger) Uses(id key.ID) []key.Use {
	var out []key.Use
	for _, u := range l.s.uses[id] {
		if l.before == 0 || u.Seq < l.before {
			out = append(out, u.Use)
		}
	}
	return out
}

// Ledger lists the uses charged so far; LedgerBefore lists those before one
// entry, so a clerk checks a step without counting its own dispatch.
func (s *State) Ledger() key.Ledger                 { return ledger{s: s} }
func (s *State) LedgerBefore(seq uint64) key.Ledger { return ledger{s: s, before: seq} }

// View for a clerk.
func (s *State) Known(root key.ID) bool           { return s.Roots[root] }
func (s *State) ChangesView() *key.Changes        { return &s.Changes }
func (s *State) Held(seq uint64) (HeldInfo, bool) { h, ok := s.held[seq]; return h, ok }

func body[T any](e Entry) (T, error) {
	var b T
	if err := json.Unmarshal(e.Body, &b); err != nil {
		return b, fmt.Errorf("entry %d %s: %w", e.Seq, e.Type, ErrCorrupt)
	}
	return b, nil
}

func (s *State) step(r stepRef) (*PlanState, *StepState) {
	p := s.Plans[r.Plan]
	if p == nil || r.Index < 0 || r.Index >= len(p.Steps) {
		return nil, nil
	}
	return p, &p.Steps[r.Index]
}

// Apply folds one entry. It is deterministic and does no I/O, so the live
// kernel, a replay and an audit reach the same state.
func (s *State) Apply(e Entry) error {
	if e.Seq != s.Seq+1 {
		return fmt.Errorf("entry %d after %d: %w", e.Seq, s.Seq, ErrCorrupt)
	}
	s.Seq = e.Seq
	switch e.Type {
	case TKeyIssued:
		b, err := body[keyIssued](e)
		if err != nil {
			return err
		}
		if len(b.Key.Links) == 0 {
			if key.CheckChain(b.Key, s.Owner) == nil {
				s.Roots[b.Key.Tip()] = true
			}
		}
	case TKeyRevoked, TKeyPaused, TKeyResumed:
		b, err := body[keyID](e)
		if err != nil {
			return err
		}
		switch e.Type {
		case TKeyRevoked:
			s.Changes.Revoked[b.ID] = true
		case TKeyPaused:
			s.Changes.Paused[b.ID] = true
		default:
			delete(s.Changes.Paused, b.ID)
		}
	case TStop:
		s.Stopped, s.Changes.Stopped = true, true
	case TResume:
		s.Stopped, s.Changes.Stopped = false, false
	case TPlanSubmit:
		b, err := body[Plan](e)
		if err != nil {
			return err
		}
		if s.Plans[b.ID] == nil {
			s.Plans[b.ID] = &PlanState{Plan: b, Seq: e.Seq, Status: SPending}
			s.Order = append(s.Order, b.ID)
		}
	case TPlanAccepted:
		b, err := body[planAccepted](e)
		if err != nil {
			return err
		}
		if p := s.Plans[b.Plan]; p != nil && p.Seq == b.Cause && p.Status == SPending {
			p.Status, p.Root, p.Scopes = SActive, b.Root, b.Scopes
			p.Steps = make([]StepState, len(p.Plan.Steps))
			for i := range p.Steps {
				p.Steps[i].Phase = PQueued
			}
		}
	case TPlanRejected:
		b, err := body[planRejected](e)
		if err != nil {
			return err
		}
		if p := s.Plans[b.Plan]; p != nil && p.Seq == b.Cause && p.Status == SPending {
			p.Status = SRejected
		}
	case TPlanCancel:
		b, err := body[planCancel](e)
		if err != nil {
			return err
		}
		if p := s.Plans[b.Plan]; p != nil && p.Status == SActive {
			p.Status = SCancelled
			if st := &p.Steps[p.Next]; st.Phase == PQueued || st.Phase == PHeld || st.Phase == PRedo {
				st.Phase = PCancelled
			}
		}
	case TStepHeld:
		b, err := body[stepHeld](e)
		if err != nil {
			return err
		}
		if _, st := s.step(b.stepRef); st != nil && st.Phase == PQueued {
			st.Phase, st.HeldSeq, st.HeldAt, st.Novel = PHeld, e.Seq, e.At, b.Novel
			s.held[e.Seq] = HeldInfo{Plan: b.Plan, Index: b.Index, At: e.At, Novel: b.Novel}
		}
	case TStepDispatch:
		b, err := body[stepDispatch](e)
		if err != nil {
			return err
		}
		if p, st := s.step(b.stepRef); st != nil && (st.Phase == PQueued || st.Phase == PHeld || st.Phase == PRedo) {
			st.Phase, st.Attempt = PInflight, b.Attempt
			if b.Attempt == 1 {
				st.DispatchSeq = e.Seq
				sp := p.Plan.Step(b.Index)
				for _, id := range p.Scopes {
					s.uses[id] = append(s.uses[id], usedRec{e.Seq, key.Use{At: e.At, Amount: sp.Amount, Recipient: sp.Recipient, Task: sp.Task}})
				}
			}
		}
	case TStepResult:
		b, err := body[stepResult](e)
		if err != nil {
			return err
		}
		if p, st := s.step(b.stepRef); st != nil && st.Phase == PInflight && b.Idem == Idem(b.Plan, b.Index) {
			switch b.Outcome {
			case "ok":
				s.complete(p, b.Index, e.At)
			case "failed":
				st.Phase = PFailed
				if p.Status == SActive {
					p.Status = SFailed
				}
			default:
				st.Phase, st.NextProbe = PUnknown, e.At+ProbeEvery
			}
		}
	case TStepProbed:
		b, err := body[stepProbed](e)
		if err != nil {
			return err
		}
		if p, st := s.step(b.stepRef); st != nil && (st.Phase == PUnknown || st.Phase == PParked) {
			switch b.Outcome {
			case "done":
				s.complete(p, b.Index, e.At)
			case "notdone":
				st.Phase = PRedo
				if p.Status != SActive {
					st.Phase = PCancelled
				}
			default:
				st.Checks++
				st.NextProbe = e.At + ProbeEvery
				if st.Checks >= MaxChecks {
					st.Phase = PParked
				}
			}
		}
	case TStepUndone:
		b, err := body[stepRef](e)
		if err != nil {
			return err
		}
		if p, st := s.step(b); st != nil && st.Phase == PDone && !st.Undone {
			st.Undone = true
			sp := p.Plan.Step(b.Index)
			s.seen[p.Root][Shape(sp)]--
			if c, _ := key.ClassOf(sp.Verb); !c.Irreversible() {
				delete(s.recent[p.Root], Fingerprint(sp)) // an irreversible effect stays done
			}
		}
	default:
		return ErrUnknown
	}
	return nil
}

// complete records a step that took effect: it advances the plan and counts
// toward the key's history.
func (s *State) complete(p *PlanState, i int, at int64) {
	p.Steps[i].Phase = PDone
	sp := p.Plan.Step(i)
	if s.seen[p.Root] == nil {
		s.seen[p.Root], s.recent[p.Root] = map[string]int{}, map[string]int64{}
	}
	s.seen[p.Root][Shape(sp)]++
	s.recent[p.Root][Fingerprint(sp)] = at
	if p.Status == SActive && p.Next == i {
		p.Next++
		if p.Next == len(p.Steps) {
			p.Status = SDone
			p.Next = len(p.Steps) - 1
		}
	}
}
