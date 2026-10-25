package kernel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Limits on a plan and on reconciliation.
const (
	// GrantHold is how long a passkey grant waits before it is live, with
	// the owner told and able to cancel it by revoking it (D-146).
	GrantHold  = key.DayMS
	MaxSteps   = 64
	MaxChecks  = 10     // KRN-8: parked after ten checks
	ProbeEvery = 60_000 // ms between reconciliation checks
	UnsentWait = 30_000 // ms before a step whose clerk was not reached is first sent again
	// MaxUnsentWait caps the wait, which doubles at each unsent attempt, so
	// a clerk down for a day costs a step about 95 resends (190 entries),
	// not thousands.
	MaxUnsentWait = UnsentWait << 5
)

// unsentWait is the wait after the attempt-th dispatch of a step reached no
// clerk.
func unsentWait(attempt int) int64 { return int64(UnsentWait) << min(max(attempt-1, 0), 5) }

// Clerk answers that say no byte reached the clerk (KRN-7): a dispatch that
// sent nothing, and a probe that could not ask.
const (
	OUnsent    = "unsent"
	OUnreached = "unreached"
)

// Entry types, all version 1. The set is closed (LOG-5).
const (
	TKeyIssued     = "key.issued"
	TKeyRevoked    = "key.revoked"
	TKeyPaused     = "key.paused"
	TKeyResumed    = "key.resumed"
	TEnrolled      = "passkey.enrolled"
	TUnenrolled    = "passkey.revoked"
	TLine          = "line.set"
	TStop          = "stop"
	TResume        = "resume"
	TPlanSubmit    = "plan.submitted"
	TPlanAccepted  = "plan.accepted"
	TPlanRejected  = "plan.rejected"
	TPlanCancel    = "plan.cancelled"
	TStepHeld      = "step.held"
	TStepDispatch  = "step.dispatched"
	TStepResult    = "step.result"
	TStepProbed    = "step.probed"
	TStepUndone    = "step.undone"
	TStepRetried   = "step.retried"
	TModelUsed     = "model.used"
	TSpendReserved = "model.reserved"
	TSpendHeld     = "spend.held"
	TSpendExtend   = "spend.extended"
	TPoolRead      = "pool.read"
	TReserveUp     = "pool.reserve.raised"
	TReserveDown   = "pool.reserve.lowered"
	TPoolReset     = "pool.reset"
	// Task entries are in task.go.
)

// schema is each entry type's body version. key.issued is 2: its body became
// a grant batch (#2663), so a log written before cannot fold it as one
// (#2670 item 4).
var schema = map[string]int{
	TKeyIssued: 2, TKeyRevoked: 1, TKeyPaused: 1, TKeyResumed: 1, TEnrolled: 1, TUnenrolled: 1, TLine: 1, TStop: 1, TResume: 1,
	TPlanSubmit: 1, TPlanAccepted: 1, TPlanRejected: 1, TPlanCancel: 1,
	TStepHeld: 1, TStepDispatch: 1, TStepResult: 1, TStepProbed: 1, TStepUndone: 1, TStepRetried: 1,
	TModelUsed: 1, TSpendReserved: 1, TSpendHeld: 1, TSpendExtend: 1, TPoolRead: 1, TReserveUp: 1, TReserveDown: 1, TPoolReset: 1,
	TTaskOpened: 1, TTaskApproved: 1, TTaskEnded: 1, TAnchorsSet: 1,
}

// Known reports whether the log may hold this type at this version.
func Known(typ string, v int) bool { got, ok := schema[typ]; return ok && got == v }

// Widening entries grant power back: a resume, a key, a passkey, the first
// anchors (setup), the owner's RETRY,
// which lets an effect that may have happened run again, and the spend and
// pool entries that reopen budget. Only one that an anchor covers counts
// after a restart (KRN-7, KRN-8).
func Widening(typ string) bool {
	return typ == TResume || typ == TKeyIssued || typ == TKeyResumed || typ == TEnrolled || typ == TLine || typ == TStepRetried ||
		typ == TReserveDown || typ == TSpendExtend || typ == TPoolReset || typ == TTaskApproved || typ == TAnchorsSet
}

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
	// Cosigns are a very large one-off's second passkey (OneOff).
	Cosigns []key.Cosign `json:"cosigns,omitempty"`
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
func VerifyPlan(p Plan, owners []ed25519.PublicKey) (*key.Verified, error) {
	if !p.text() {
		return nil, ErrNotText
	}
	return key.Verify(p.Key, owners, p.use(), p.Sig)
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
func (p Plan) Step(i int) key.Step { return Normalize(p.Task(), p.Steps[i]) }

// Task is what the plan's steps and metered calls are charged under
// (key.ChargeTask).
func (p Plan) Task() string { return key.ChargeTask(p.Key, p.ID) }

// Entry bodies.
type (
	// grants is one batch of passkey grants: roots and the first links off
	// them, under one hold (D-146).
	grantBatch struct {
		Keys    []key.Key
		Cosigns []key.Cosign `json:",omitempty"` // a big batch's second passkey
	}
	// lineSet is the owner's line for a big change, in percent (D-146).
	lineSet struct {
		Percent int64
		Cosigns []key.Cosign `json:",omitempty"`
	}
	enrolled   struct{ Enrollment key.Enrollment }
	unenrolled struct{ Passkey ed25519.PublicKey }
	keyID      struct{ ID key.ID }
	// modelUsed is usage a clerk metered itself, charged to the key it cites (LOG-7).
	modelUsed struct {
		Root   key.ID   `json:"root"`
		Scopes []key.ID `json:"scopes"`
		Task   string   `json:"task"` // the plan the usage was charged to
		Route  string   `json:"route"`
		Amount int64    `json:"amount"`
		Source string   `json:"source"` // "provider", "clerk" or "admitted" (the worst case): whose count this is
		// Settles is the reservation entry this usage replaces (AdmitSpend).
		Settles uint64 `json:"settles"`
	}
	// spendReserved is a metered call's worst case, charged from its
	// admission until its usage settles it (#2613 item 1).
	spendReserved struct {
		Root   key.ID   `json:"root"`
		Scopes []key.ID `json:"scopes"`
		Task   string   `json:"task"` // the plan admitted
		Amount int64    `json:"amount"`
	}
	// spendHeld stops a task whose spend cap is used up until the owner extends it (LOG-7).
	spendHeld struct {
		Plan    string `json:"plan"`
		Code    string `json:"code"`
		Detail  string `json:"detail"`
		Root    key.ID `json:"root"`    // the root of the key the plan cites: it cannot release itself
		Funding key.ID `json:"funding"` // the key funding the plan when held: nor can anything under it
	}
	// spendExtended releases a held plan and names the owner-envelope key its
	// later calls are charged to. It widens: it needs an anchor (KRN-7).
	spendExtended struct {
		Plan string  `json:"plan"`
		Key  key.Key `json:"key"`
	}
	// poolRead is the provider's own figure for a pool (RES-5), in per mille.
	poolRead struct {
		Pool    string `json:"pool"`
		Used    int64  `json:"used"`
		ResetAt int64  `json:"reset_at"`
	}
	// poolReset reopens a pool at the reset time the provider gave: it clears the
	// reading, so it widens and needs an anchor (RES-5, KRN-7).
	poolReset struct {
		Pool string `json:"pool"`
	}
	poolReserve struct {
		Pool    string `json:"pool"`
		Reserve int64  `json:"reserve"` // per mille of the pool kept for the owner
	}
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
		Covered string `json:"covered,omitempty"`
	}
	stepProbed struct {
		stepRef
		Outcome string `json:"outcome"`           // done, notdone, unknown
		Covered string `json:"covered,omitempty"` // a covered submit's line, when its answer was lost (CLK-3)
	}
)

// Step phases.
const (
	PQueued    = "queued"
	PHeld      = "held"
	PInflight  = "inflight"
	PUnknown   = "unknown"
	PRedo      = "redo"
	PUnsent    = "unsent" // the clerk was not reached: nothing was sent, so it is sent again after UnsentWait
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
	Detail      string // the clerk's last answer, for STATUS
	Covered     string // a covered submit's STATUS line (CLK-3)
	SentAt      int64  // when the log first recorded it sent; a covered step's, when it was done
	Retried     bool   // RETRY sent it again: it may have acted until a probe finds it not done
}

type PlanState struct {
	Plan   Plan
	Seq    uint64 // the submission entry
	Status string
	Root   key.ID
	Scopes []key.ID
	Next   int
	Steps  []StepState
	// Cancel is why a cancelled plan was cancelled, for STATUS: the code
	// ("owner", a key refusal, or no-clerk) and its detail (OWN-17).
	Cancel, CancelDetail string
}

// SpendHold is why a plan's spend is stopped. Root is the root of the key the
// plan cites and Funding the key that was funding it; neither, nor anything
// under them, can release the hold.
type SpendHold struct {
	Code, Detail  string
	Root, Funding key.ID
}

// Pool is what the log knows of one usage pool (RES-5).
type Pool struct{ Used, ResetAt, Reserve int64 }

// PoolOpen reports whether work may draw on a pool: below the owner's reserve.
func (s *State) PoolOpen(name string) bool {
	p, ok := s.Pools[name]
	return !ok || p.Used+p.Reserve < PoolFull
}

// PoolDue reports whether a pool at its reserve has passed the reset time the
// provider gave, which is the cooldown. The reopening is a logged widening.
func (s *State) PoolDue(now int64, name string) bool {
	p := s.Pools[name]
	return !s.PoolOpen(name) && p.ResetAt > 0 && now >= p.ResetAt
}

// PoolWindowMS is the window a pool is declared to reset over (RES-5): the
// cooldown of a full pool whose reading gave no usable reset time.
const PoolWindowMS = 5 * 3600 * 1000

// PoolFull is a whole pool, in per mille.
const PoolFull = 1000

type usedRec struct {
	Seq uint64
	key.Use
}

// cancelUnsent cancels step st of plan p, which nothing has sent since it
// was last known not to have acted: queued, unsent, or proved not done. Its
// dispatch's charge comes off the ledger, so a cancel leaves no cap spent on
// an effect that never happened (KRN-8). A step RETRY sent again may have
// acted before it parked, so it goes back to parked, charged and listed.
func (s *State) cancelUnsent(p *PlanState, st *StepState) {
	if st.Retried {
		st.Phase = PParked
		return
	}
	st.Phase = PCancelled
	for _, id := range p.Scopes {
		s.uses[id] = slices.DeleteFunc(s.uses[id], func(u usedRec) bool { return u.Seq == st.DispatchSeq })
	}
}

// State is the log folded: the only input to Decide besides the event.
type State struct {
	// The owner's passkeys (D-146): the anchors, the hardware keys; each
	// passkey an anchor enrolled; less those revoked.
	Anchors    []ed25519.PublicKey
	Enrolled   []key.Enrollment
	Unenrolled []ed25519.PublicKey
	Seq        uint64
	Stopped    bool
	Stops      uint64 // STOPs logged; a RESUME names the count it lifts (#3078)
	Changes    key.Changes
	// Grants are the passkey's grants in the log, roots and first links,
	// each live from its time (D-146).
	Grants map[key.ID]Grant
	// Line is the owner's line for a big change, in percent; 0 is DefaultLine.
	Line  int64
	lines int // line changes so far, named in each one's co-signature
	Plans map[string]*PlanState
	// SpendHeld lists the tasks stopped on a used-up spend cap; Pools the usage pools.
	SpendHeld map[string]SpendHold
	// Extended maps a plan to the extension key its later calls are charged to.
	Extended map[string]key.Key
	Pools    map[string]Pool
	tasks    map[string]*taskState
	Order    []string
	uses     map[key.ID][]usedRec
	reserved map[uint64]*spendReserved   // open reservations by entry
	seen     map[key.ID]map[string]int   // root -> shape -> completed, not undone
	recent   map[key.ID]map[string]int64 // root -> fingerprint -> time of last completion
}

// Grant is a passkey grant and when it is live.
type Grant struct {
	Key  key.Key
	From int64
}

func NewState(anchors []ed25519.PublicKey) *State {
	return &State{
		Anchors: anchors,
		Changes: key.Changes{Revoked: map[key.ID]bool{}, Paused: map[key.ID]bool{}},
		Grants:  map[key.ID]Grant{}, Plans: map[string]*PlanState{},
		SpendHeld: map[string]SpendHold{}, Extended: map[string]key.Key{}, Pools: map[string]Pool{},
		tasks: map[string]*taskState{}, uses: map[key.ID][]usedRec{}, reserved: map[uint64]*spendReserved{},
		seen: map[key.ID]map[string]int{}, recent: map[key.ID]map[string]int64{},
	}
}

// Replay folds a whole log.
func Replay(anchors []ed25519.PublicKey, es []Entry) (*State, error) {
	s := NewState(anchors)
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
// as owner or clerk sourced; the task is task (Plan.Task, key.ChargeTask), the recipient is the verb's object
// argument and the amount is the "amount" argument in its one canonical
// spelling, any other (010, +10) unreadable and so negative, which Authorize
// refuses; one spelling per number keeps the duplicate fingerprint exact. The kernel, the clerk and a replay all see
// this step (KEY-2, KRN-3). Content and labels stay the planner's claims; a
// clerk with facts checks them (CLK-2).
func Normalize(task string, s PlanStep) key.Step {
	args := make(map[string]key.Arg, len(s.Args))
	for n, v := range s.Args {
		args[n] = key.Arg{Value: v, Source: key.SrcPlanner}
	}
	out := key.Step{Verb: s.Verb, Clerk: s.Clerk, Args: args, Content: s.Content,
		Labels: append([]string(nil), s.Labels...), Task: task, Recipient: s.Args[key.RecipientArg(s.Verb)]}
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
	s       *State
	before  uint64 // 0: every use
	settled bool   // leave out reservations still open
}

func (l ledger) Uses(id key.ID) []key.Use {
	var out []key.Use
	for _, u := range l.s.uses[id] {
		if (l.before == 0 || u.Seq < l.before) && (!l.settled || l.s.reserved[u.Seq] == nil) {
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
func (s *State) ChangesView() *key.Changes { return &s.Changes }

// Granted is when the grant id is live, if the log holds it.
func (s *State) Granted(id key.ID) (int64, bool) { g, ok := s.Grants[id]; return g.From, ok }

// Enrollments is what Passkeys reads, for a clerk to check with its own anchors.
func (s *State) Enrollments() ([]key.Enrollment, []ed25519.PublicKey) {
	return s.Enrolled, s.Unenrolled
}

// Passkeys is the owner's set (D-146).
func (s *State) Passkeys() []ed25519.PublicKey {
	return key.Passkeys(s.Anchors, s.Enrolled, s.Unenrolled)
}

// Pending lists the grants still in their hold and not cancelled, for the
// owner's notice.
func (s *State) Pending(now int64) []key.ID {
	var out []key.ID
	for id, g := range s.Grants {
		if now < g.From && !s.Changes.Revoked[id] && !s.Changes.Revoked[rootOf(g.Key)] {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i][:], out[j][:]) < 0 })
	return out
}

// ErrNotAGrant refuses a key that is neither a root nor a first link off a
// root in the log or the same batch.
var ErrNotAGrant = errors.New("kernel: only a root or a first link off a granted root is granted")

// grants decides one batch logged at at, in order: the grants it adds, or
// the first refusal. A big batch needs its second passkey, as a whole. The
// fold and Issue share it, so Issue logs only what the fold grants.
func (s *State) grants(keys []key.Key, cos []key.Cosign, at int64) (map[key.ID]Grant, error) {
	out := map[key.ID]Grant{}
	if s.big(keys, at) && !s.cosigned(keys, cos) {
		return out, ErrNeedsCosign
	}
	for _, k := range keys {
		from, err := s.decide(k, at, out)
		if err != nil {
			return out, err
		}
		if _, ok := s.Grants[k.Tip()]; !ok {
			if _, ok := out[k.Tip()]; !ok {
				out[k.Tip()] = Grant{Key: k, From: from}
			}
		}
	}
	return out, nil
}

// decide is when grant k, logged at at, is live. A root waits GrantHold. So
// does a first link, never less than its root, but a renewal of a live grant
// at the same limits is live at once (renews).
func (s *State) decide(k key.Key, at int64, batch map[key.ID]Grant) (int64, error) {
	if len(k.Links) > 1 {
		return 0, ErrNotAGrant
	}
	if _, err := key.Chain(k, s.Passkeys()); err != nil {
		return 0, err
	}
	from := at + GrantHold
	if len(k.Links) == 0 {
		return from, nil
	}
	// A clerk key lives at most ClerkLife once live: a tap cannot sign one
	// that runs for years (D-146).
	if exp := lapse(k.Links[0].Caveats); exp == nil || *exp > from+key.ClerkLife {
		return 0, ErrLife
	}
	r, ok := batch[rootOf(k)]
	if !ok {
		if r, ok = s.Grants[rootOf(k)]; !ok {
			return 0, ErrNotAGrant
		}
	}
	if s.renews(k, at) {
		from = at
	}
	return max(from, r.From), nil
}

// renews reports whether k renews a live clerk key: same root and holder,
// limits within the old key's (a renewal may narrow, never widen) and a later
// expiry, and neither lapsed, paused nor revoked (D-146, #2670 item 5).
func (s *State) renews(k key.Key, at int64) bool {
	exp := lapse(k.Links[0].Caveats)
	lim, err := key.Fold(k.Links[0].Caveats)
	if exp == nil || *exp > at+key.ClerkLife || err != nil {
		return false
	}
	for id, g := range s.Grants {
		if len(g.Key.Links) != 1 || g.From > at || s.Changes.Revoked[id] || s.Changes.Paused[id] ||
			rootOf(g.Key) != rootOf(k) || !bytes.Equal(g.Key.Links[0].Holder, k.Links[0].Holder) {
			continue
		}
		old := lapse(g.Key.Links[0].Caveats)
		was, err := key.Fold(g.Key.Links[0].Caveats)
		if old != nil && *old > at && *exp >= *old && err == nil && lim.Within(was) {
			return true
		}
	}
	return false
}

// ErrLife refuses a clerk key that would live past ClerkLife once live.
var ErrLife = errors.New("kernel: a clerk key lives at most ClerkLife once live")

// lapse is when caveats cs stop a key: the earliest expiry.
func lapse(cs []key.Caveat) *int64 {
	var exp *int64
	for _, c := range cs {
		if c.Kind == key.KExpires && (exp == nil || c.N < *exp) {
			n := c.N
			exp = &n
		}
	}
	return exp
}

func rootOf(k key.Key) key.ID { return key.Key{Root: k.Root}.Tip() }

// owners is the passkey set a plan's key is verified against (PlanOwners).
func (s *State) owners(k key.Key) []ed25519.PublicKey { return PlanOwners(s, s.Anchors, k) }

// PlanOwners is the passkey set a plan's key is verified against, in the
// kernel and the clerk alike, from the checker's own anchors. For a key
// derived from a granted root it holds every passkey an anchor enrolled, cut
// off since or not, so grants stand after their passkey is cut off: the
// grant itself was checked against the set at its entry. For a bare root it
// is the set now: only a passkey's own tap uses a bare root, and a cut-off
// phone taps nothing (D-146).
func PlanOwners(v View, anchors []ed25519.PublicKey, k key.Key) []ed25519.PublicKey {
	es, un := v.Enrollments()
	if _, ok := v.Granted(rootOf(k)); ok && len(k.Links) > 0 {
		un = nil
	}
	return key.Passkeys(anchors, es, un)
}

// Dispatched is the log's record of r: it answers only when r's step is in
// flight and r carries exactly the plan the log admitted. A request for a step
// the kernel is not running now, stale or forged, or another plan signed under
// a logged id, gets nothing, and the clerk refuses it (CLK-2, KRN-8).
func (s *State) Dispatched(r Request) (Dispatch, bool) {
	p, st := s.step(stepRef{r.Plan.ID, r.Index})
	if st == nil || st.Phase != PInflight || st.DispatchSeq == 0 || !reflect.DeepEqual(r.Plan, p.Plan) {
		return Dispatch{}, false
	}
	return Dispatch{Seq: st.DispatchSeq, Held: st.HeldSeq != 0, HeldAt: st.HeldAt, Novel: st.Novel}, true
}

// Unsettled is a step whose effect is uncertain: still being reconciled, or
// parked after MaxChecks. STATUS lists every one (KRN-8, OWN-16).
type Unsettled struct {
	Plan   string
	Index  int
	Verb   key.Verb
	Clerk  string
	Phase  string // PUnknown, PParked, or PUnsent: its clerk was not reached
	Checks int
	Detail string // the clerk's last answer
	Retry  bool   // the owner may RETRY it
	SentAt int64  // when it was first sent (unix ms), which a RETRY line names (#3079)
	// What the owner's RETRY tier is judged on (CH-10, CH-11), from the
	// plan's own step: its spend, whether its verb moves money (always
	// the high tier), and its recipient.
	Amount    int64
	Money     bool
	Recipient string
	// The plan's status, and why it was cancelled: a cancelled plan's step
	// stays listed while it may have acted, but nothing more is tried.
	PlanStatus           string
	Cancel, CancelDetail string
}

// Status lists the unsettled steps in submission order.
func (s *State) Status() []Unsettled {
	var out []Unsettled
	for _, id := range s.Order {
		p := s.Plans[id]
		for i := range p.Steps {
			st := &p.Steps[i]
			if st.Phase != PUnknown && st.Phase != PParked && st.Phase != PUnsent {
				continue
			}
			ks := p.Plan.Step(i)
			out = append(out, Unsettled{Plan: id, Index: i, Verb: ks.Verb, Clerk: ks.Clerk,
				Phase: st.Phase, Checks: st.Checks, Detail: st.Detail, Retry: retryable(p, st), SentAt: st.SentAt,
				Amount: ks.Amount, Money: slices.Contains(key.ArgNames(ks.Verb), key.ArgAmount), Recipient: ks.Recipient,
				PlanStatus: p.Status, Cancel: p.Cancel, CancelDetail: p.CancelDetail})
		}
	}
	return out
}

// MaxShown bounds a clerk's line in STATUS.
const MaxShown = 256

// shown reports whether a clerk's text may go to the owner as one STATUS
// line: bounded, valid UTF-8, no control characters.
func shown(s string) bool {
	return len(s) <= MaxShown && utf8.ValidString(s) && !strings.ContainsFunc(s, unseen)
}

// unseen is a rune that reshapes or hides the line the owner reads: a
// control, a line or paragraph separator, or a format character such as a
// bidi override, an invisible space or a tag. Only the two joiners are
// shown: U+200D builds an emoji from parts (a button labelled with a
// family emoji), and U+200C shapes Persian and Indic words. Neither
// reorders text or carries any of its own (#2740).
func unseen(r rune) bool {
	if r == '\u200c' || r == '\u200d' {
		return false
	}
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

// CoveredLine is a submit a task approval covered, listed in STATUS once sent
// (CLK-3).
type CoveredLine struct {
	Plan  string
	Index int
	Clerk string
	Line  string
	At    int64
}

// Covered lists the covered submits sent within TaskTimeout before now, the
// longest a task approval lives, oldest first (CLK-3, #2705).
func (s *State) Covered(now int64) []CoveredLine {
	var out []CoveredLine
	for _, id := range s.Order {
		p := s.Plans[id]
		for i, st := range p.Steps {
			if st.Covered != "" && now-st.SentAt < TaskTimeout {
				out = append(out, CoveredLine{id, i, p.Plan.Step(i).Clerk, st.Covered, st.SentAt})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At < out[j].At })
	return out
}

// retryable: only a parked step of a live plan. The owner's cancel stands,
// and a step still being reconciled may yet prove done.
func retryable(p *PlanState, st *StepState) bool { return st.Phase == PParked && p.Status == SActive }

// sendable reports whether a step in phase may be dispatched: nothing of it
// has reached a clerk yet, or what did is known not to have taken effect.
func sendable(phase string) bool {
	return phase == PQueued || phase == PHeld || phase == PRedo || phase == PUnsent
}

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

// planTask is the task plan's metered usage is charged under (Plan.Task).
func (s *State) planTask(plan string) string {
	if p := s.Plans[plan]; p != nil {
		return p.Plan.Task()
	}
	return key.PlanPrefix + plan
}

// Apply folds one entry. It is deterministic and does no I/O, so the live
// kernel, a replay and an audit reach the same state.
func (s *State) Apply(e Entry) error {
	if e.Seq != s.Seq+1 {
		return fmt.Errorf("entry %d after %d: %w", e.Seq, s.Seq, ErrCorrupt)
	}
	s.Seq = e.Seq
	switch e.Type {
	case TAnchorsSet:
		return s.applySetup(e)
	case TKeyIssued:
		b, err := body[grantBatch](e)
		if err != nil {
			return err
		}
		add, _ := s.grants(b.Keys, b.Cosigns, e.At) // a refused key adds nothing, nor any after it
		for id, g := range add {
			s.Grants[id] = g
		}
	case TEnrolled:
		b, err := body[enrolled](e)
		if err != nil {
			return err
		}
		s.Enrolled = append(s.Enrolled, b.Enrollment)
	case TLine:
		b, err := body[lineSet](e)
		if err != nil {
			return err
		}
		if s.lineOK(b) == nil {
			s.Line, s.lines = b.Percent, s.lines+1
		}
	case TUnenrolled:
		b, err := body[unenrolled](e)
		if err != nil {
			return err
		}
		if key.In(s.Anchors, b.Passkey) {
			break // ErrAnchor
		}
		s.Unenrolled = append(s.Unenrolled, b.Passkey)
		s.dropApprovals(b.Passkey)
		// Its grants still in their hold are cancelled with it: a lost
		// phone's last taps never go live (D-146).
		for id, g := range s.Grants {
			if e.At < g.From && key.SignedBy(g.Key, b.Passkey) {
				s.Changes.Revoked[id] = true
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
	case TSpendReserved:
		b, err := body[spendReserved](e)
		if err != nil {
			return err
		}
		s.reserved[e.Seq] = &b
		for _, id := range b.Scopes {
			s.uses[id] = append(s.uses[id], usedRec{e.Seq, key.Use{At: e.At, Amount: b.Amount, Task: s.planTask(b.Task)}})
		}
	case TModelUsed:
		b, err := body[modelUsed](e)
		if err != nil {
			return err
		}
		if rs := s.reserved[b.Settles]; rs != nil && rs.Task == b.Task {
			delete(s.reserved, b.Settles)
			for _, id := range rs.Scopes {
				s.uses[id] = slices.DeleteFunc(s.uses[id], func(u usedRec) bool { return u.Seq == b.Settles })
			}
		}
		for _, id := range b.Scopes {
			s.uses[id] = append(s.uses[id], usedRec{e.Seq, key.Use{At: e.At, Amount: b.Amount, Task: s.planTask(b.Task)}})
		}
	case TSpendHeld:
		b, err := body[spendHeld](e)
		if err != nil {
			return err
		}
		s.SpendHeld[b.Plan] = SpendHold{b.Code, b.Detail, b.Root, b.Funding}
	case TSpendExtend:
		b, err := body[spendExtended](e)
		if err != nil {
			return err
		}
		delete(s.SpendHeld, b.Plan)
		s.Extended[b.Plan] = b.Key
	case TPoolRead:
		b, err := body[poolRead](e)
		if err != nil {
			return err
		}
		p := s.Pools[b.Pool]
		p.Used, p.ResetAt = b.Used, b.ResetAt
		s.Pools[b.Pool] = p
	case TPoolReset:
		b, err := body[poolReset](e)
		if err != nil {
			return err
		}
		p := s.Pools[b.Pool]
		p.Used, p.ResetAt = 0, 0
		s.Pools[b.Pool] = p
	case TReserveUp, TReserveDown:
		b, err := body[poolReserve](e)
		if err != nil {
			return err
		}
		p := s.Pools[b.Pool]
		p.Reserve = b.Reserve
		s.Pools[b.Pool] = p
	case TStop:
		s.Stopped, s.Changes.Stopped = true, true
		s.Stops++
		for _, t := range s.tasks {
			t.ended = true // an ended task never comes back
		}
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
			p.Status, p.Cancel, p.CancelDetail = SCancelled, b.Code, b.Detail
			if st := &p.Steps[p.Next]; sendable(st.Phase) {
				s.cancelUnsent(p, st)
			}
		}
	case TStepHeld:
		b, err := body[stepHeld](e)
		if err != nil {
			return err
		}
		if _, st := s.step(b.stepRef); st != nil && st.Phase == PQueued {
			st.Phase, st.HeldSeq, st.HeldAt, st.Novel = PHeld, e.Seq, e.At, b.Novel
		}
	case TStepDispatch:
		b, err := body[stepDispatch](e)
		if err != nil {
			return err
		}
		if p, st := s.step(b.stepRef); st != nil && sendable(st.Phase) {
			st.Phase, st.Attempt = PInflight, b.Attempt
			if b.Attempt == 1 {
				st.DispatchSeq, st.SentAt = e.Seq, e.At
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
			st.Detail = b.Detail
			switch b.Outcome {
			case "ok":
				s.complete(p, b.Index, e.At)
				if b.Covered != "" && shown(b.Covered) {
					st.Covered, st.SentAt = b.Covered, e.At
				}
			case OUnsent:
				st.Phase, st.NextProbe = PUnsent, e.At+unsentWait(st.Attempt)
				if p.Status != SActive {
					s.cancelUnsent(p, st) // nothing was sent, and nothing will be
				}
			case "failed":
				// A redo's failure says only that the redo did not act: the
				// send before it may have, so the step parks again, charged
				// and listed, for the owner to retry or cancel (KRN-8).
				if st.Retried {
					st.Phase = PParked
					break
				}
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
				if b.Covered != "" && shown(b.Covered) {
					st.Covered, st.SentAt = b.Covered, e.At
				}
			case "notdone":
				st.Phase, st.Retried = PRedo, false
				if p.Status != SActive {
					s.cancelUnsent(p, st)
				}
			case OUnreached:
				st.NextProbe = e.At + ProbeEvery // no check was made, so none counts
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
	case TStepRetried:
		b, err := body[stepRef](e)
		if err != nil {
			return err
		}
		// The redo runs Next's checks again: key, revocation, pause, STOP,
		// limits as of the first dispatch, under the same idempotency key.
		if p, st := s.step(b); st != nil && retryable(p, st) {
			st.Phase, st.Checks, st.Retried = PRedo, 0, true
		}
	case TTaskOpened, TTaskApproved, TTaskEnded:
		return s.applyTask(e)
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
