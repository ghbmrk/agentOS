// Package clerk is the only exit. A clerk re-checks every step against the key
// and the log's view before it acts, and acts at most once per idempotency key
// (CLK-2, KRN-8). Mail here is a synthetic mailbox: no real account is touched.
package clerk

import (
	"crypto/ed25519"
	"sync"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Facts is a clerk's own reading of what a step carries: the content class,
// flow labels and amount it computes from the arguments and the account it
// guards. The planner only claims these; a clerk that has facts refuses a
// claim that differs (KEY-2, CLK-2).
type Facts func(key.Step) (content string, labels []string, amount int64)

// RClaim is the refusal for a claim the clerk's facts contradict.
const RClaim = "claim"

// Check is the clerk's own authorization of a request. It trusts nothing the
// kernel decided: the chain and its last holder's signature on the plan, the
// step taken from that signed plan, the root's presence in the log, the key's limits
// as of the first dispatch, and for an irreversible verb the hold window.
func Check(owner ed25519.PublicKey, name string, facts Facts, r kernel.Request, v kernel.View) *key.Refusal {
	st := r.Step()
	if st.Clerk != name {
		return &key.Refusal{Code: key.RClerk, Detail: st.Clerk}
	}
	// The recipient a key's caveats judge is the verb's first argument, the
	// object the request acts on; a step claiming another is refused here.
	if a := st.Args[key.RecipientArg(st.Verb)]; st.Recipient != a.Value {
		return &key.Refusal{Code: RClaim, Detail: "step recipient differs from its object argument"}
	}
	if facts != nil {
		content, labels, amount := facts(st)
		if content != st.Content || amount != st.Amount || !sameSet(labels, st.Labels) {
			return &key.Refusal{Code: RClaim, Detail: "step claims differ from the clerk's facts"}
		}
	}
	ver, err := kernel.VerifyPlan(r.Plan, owner)
	if err != nil {
		return &key.Refusal{Code: kernel.CKey, Detail: err.Error()}
	}
	if !v.Known(ver.Root()) {
		return &key.Refusal{Code: kernel.CUnknownRoot, Detail: ver.Root().String()}
	}
	ctx := key.Context{Now: r.Now, Changes: v.ChangesView(), Ledger: v.LedgerBefore(r.DispatchSeq)}
	if rf := ver.Authorize(st, ctx); rf != nil {
		return rf
	}
	if c, ok := key.ClassOf(st.Verb); ok && c.Irreversible() && max(ver.Limits.Window(false), ver.Limits.Window(true)) > 0 {
		h, held := v.Held(r.HeldSeq)
		if !held || h.Plan != r.Plan.ID || h.Index != r.Index {
			return &key.Refusal{Code: "hold", Detail: "step was not held"}
		}
		if r.Now < h.At+ver.Limits.Window(h.Novel) {
			return &key.Refusal{Code: "hold", Detail: "window not over"}
		}
	}
	return nil
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

// Mail is a fake mail clerk over an in-memory mailbox.
type Mail struct {
	Name  string
	Owner ed25519.PublicKey
	// Fault is consulted for op "do" and "probe"; nil means no fault.
	Fault func(op string, r kernel.Request) string
	// Facts, when set, is the clerk's own reading of a step's claims; nil
	// takes the step's claims as given.
	Facts Facts

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

func (m *Mail) Do(r kernel.Request, v kernel.View) kernel.Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done[r.Idem] {
		return kernel.Result{Outcome: "ok", Detail: "already done"}
	}
	if rf := Check(m.Owner, m.Name, m.Facts, r, v); rf != nil {
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
	m.done[r.Idem] = true
	m.effects = append(m.effects, Effect{r.Idem, r.Step()})
}

func (m *Mail) Probe(r kernel.Request, _ kernel.View) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fault("probe", r) != FaultNone {
		return "unknown"
	}
	if m.done[r.Idem] {
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
