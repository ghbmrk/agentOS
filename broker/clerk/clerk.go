// Package clerk is the only exit. A clerk re-checks every step against the key
// and the log's view before it acts, and acts at most once per idempotency key
// (CLK-2, KRN-8). Mail here is a synthetic mailbox: no real account is touched.
package clerk

import (
	"bytes"
	"crypto/ed25519"
	"strconv"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Facts is a clerk's own reading of what a step carries: the content class,
// flow labels and amount it computes from the arguments and the account it
// guards. The planner only claims these, and every clerk has facts: a claim
// that differs is refused, and so is every step at a clerk without them
// (KEY-2, CLK-2).
type Facts func(key.Step) (content string, labels []string, amount int64)

// Clerk refusal codes, beside the key package's and the kernel's.
const (
	RClaim    = "claim"    // a claim the clerk's facts contradict, or no facts to judge it
	RDispatch = "dispatch" // the log has no such step in flight
	RHold     = "hold"
)

// Clock is a clerk's own time in unix ms. A nil Clock reads the wall clock.
type Clock func() int64

func (c Clock) now() int64 {
	if c == nil {
		return time.Now().UnixMilli()
	}
	return c()
}

// Check is the clerk's own authorization of a request at now, on the clerk's
// own clock. It trusts nothing the kernel or the transport says: the chain
// and its last holder's signature on the plan, the step taken from that signed
// plan, the root's presence in the log, the log's record that this very plan's
// step is in flight, the key's limits as of that step's first dispatch, and
// for an irreversible verb the hold the log recorded (CLK-2).
func Check(owner ed25519.PublicKey, name string, facts Facts, now int64, r kernel.Request, v kernel.View) *key.Refusal {
	st := r.Step()
	if st.Clerk != name {
		return &key.Refusal{Code: key.RClerk, Detail: st.Clerk}
	}
	// The recipient a key's caveats judge is the verb's first argument, the
	// object the request acts on; a step claiming another is refused here.
	if a := st.Args[key.RecipientArg(st.Verb)]; st.Recipient != a.Value {
		return &key.Refusal{Code: RClaim, Detail: "step recipient differs from its object argument"}
	}
	if facts == nil {
		return &key.Refusal{Code: RClaim, Detail: "clerk has no facts to judge the step's claims"}
	}
	if content, labels, amount := facts(st); content != st.Content || amount != st.Amount || !sameSet(labels, st.Labels) {
		return &key.Refusal{Code: RClaim, Detail: "step claims differ from the clerk's facts"}
	}
	ver, err := kernel.VerifyPlan(r.Plan, owner)
	if err != nil {
		return &key.Refusal{Code: kernel.CKey, Detail: err.Error()}
	}
	if !v.Known(ver.Root()) {
		return &key.Refusal{Code: kernel.CUnknownRoot, Detail: ver.Root().String()}
	}
	// Equal signatures over a verified plan are one plan: the signature
	// covers the key's tip, the id and every step (key.Sign).
	d, ok := v.Dispatched(r.Plan.ID, r.Index)
	if !ok || !bytes.Equal(d.Sig, r.Plan.Sig) {
		return &key.Refusal{Code: RDispatch, Detail: "the log has no such step in flight"}
	}
	ctx := key.Context{Now: now, Changes: v.ChangesView(), Ledger: v.LedgerBefore(d.Seq)}
	if rf := ver.Authorize(st, ctx); rf != nil {
		return rf
	}
	if c, ok := key.ClassOf(st.Verb); ok && c.Irreversible() && max(ver.Limits.Window(false), ver.Limits.Window(true)) > 0 {
		if !d.Held {
			return &key.Refusal{Code: RHold, Detail: "step was not held"}
		}
		if now < d.HeldAt+ver.Limits.Window(d.Novel) {
			return &key.Refusal{Code: RHold, Detail: "window not over"}
		}
	}
	return nil
}

// amountOf is a clerk's own reading of the amount argument: its one canonical
// spelling, any other unreadable and so -1; 0 when the verb has none.
func amountOf(s key.Step) int64 {
	a, ok := s.Args[key.ArgAmount]
	if !ok {
		return 0
	}
	n, err := strconv.ParseInt(a.Value, 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != a.Value {
		return -1
	}
	return n
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

// Fault names an injected failure for tests and the sim.
const (
	FaultNone    = ""
	FaultFail    = "fail"     // refuses before acting
	FaultDrop    = "drop"     // no effect, no answer
	FaultLostAck = "lost-ack" // effect applied, no answer
)

// Effect is one applied step, kept so an invariant can count them.
type Effect struct {
	Idem string
	Step key.Step
}

// Mail is a fake mail clerk over an in-memory mailbox. The sim runs this
// same code, so what the sim proves of a clerk it proves of this one.
type Mail struct {
	Name  string
	Owner ed25519.PublicKey
	// Fault is consulted for op "do" and "probe"; nil means no fault.
	Fault func(op string, r kernel.Request) string
	Clock Clock
	// Content and Labels are how the mailbox reads every step's data: its
	// facts, with the amount argument (KEY-2).
	Content string
	Labels  []string

	mu      sync.Mutex
	done    map[string]bool
	effects []Effect
}

func NewMail(name string, owner ed25519.PublicKey) *Mail {
	return &Mail{Name: name, Owner: owner, done: map[string]bool{}}
}

func (m *Mail) fault(op string, r kernel.Request) string {
	if m.Fault == nil {
		return FaultNone
	}
	return m.Fault(op, r)
}

// Facts is the mailbox's own reading of a step.
func (m *Mail) Facts(s key.Step) (string, []string, int64) { return m.Content, m.Labels, amountOf(s) }

func (m *Mail) Do(r kernel.Request, v kernel.View) kernel.Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done[r.Idem()] {
		return kernel.Result{Outcome: "ok", Detail: "already done"}
	}
	if rf := Check(m.Owner, m.Name, m.Facts, m.Clock.now(), r, v); rf != nil {
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	switch m.fault("do", r) {
	case FaultFail:
		return kernel.Result{Outcome: "failed", Detail: "fault"}
	case FaultDrop:
		return kernel.Result{Outcome: "unknown", Detail: "no answer"}
	case FaultLostAck:
		m.apply(r)
		return kernel.Result{Outcome: "unknown", Detail: "no answer"}
	}
	m.apply(r)
	return kernel.Result{Outcome: "ok"}
}

func (m *Mail) apply(r kernel.Request) {
	m.done[r.Idem()] = true
	m.effects = append(m.effects, Effect{r.Idem(), r.Step()})
}

func (m *Mail) Probe(r kernel.Request, _ kernel.View) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fault("probe", r) != FaultNone {
		return "unknown"
	}
	if m.done[r.Idem()] {
		return "done"
	}
	return "notdone"
}

// Effects returns a copy of the applied steps, in order.
func (m *Mail) Effects() []Effect {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Effect(nil), m.effects...)
}
