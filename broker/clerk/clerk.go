// Package clerk is the only exit. A clerk re-checks every step against the key
// and the log's view before it acts, and acts at most once per idempotency key
// (CLK-2, KRN-8). Mail here is a synthetic mailbox: no real account is touched.
package clerk

import (
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/check"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Clock is a clerk's own time in unix ms. A nil Clock reads the wall clock.
type Clock func() int64

// Now is the clock's time.
func (c Clock) Now() int64 {
	if c == nil {
		return time.Now().UnixMilli()
	}
	return c()
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
	Name string
	// Anchors are the owner's hardware keys, the clerk's own trust root.
	Anchors []key.PublicKey
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

func NewMail(name string, anchors []key.PublicKey) *Mail {
	return &Mail{Name: name, Anchors: anchors, done: map[string]bool{}}
}

func (m *Mail) fault(op string, r kernel.Request) string {
	if m.Fault == nil {
		return FaultNone
	}
	return m.Fault(op, r)
}

// Facts is the mailbox's own reading of a step.
func (m *Mail) Facts(s key.Step) (string, []string, int64) {
	return m.Content, m.Labels, check.Amount(s)
}

func (m *Mail) Do(r kernel.Request, v kernel.View) kernel.Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done[r.Idem()] {
		return kernel.Result{Outcome: "ok", Detail: "already done"}
	}
	if rf := check.Check(m.Anchors, m.Name, m.Facts, m.Clock.Now(), r, v); rf != nil {
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

func (m *Mail) Probe(r kernel.Request, _ kernel.View) kernel.Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fault("probe", r) != FaultNone {
		return kernel.Result{Outcome: "unknown"}
	}
	if m.done[r.Idem()] {
		return kernel.Result{Outcome: "done"}
	}
	return kernel.Result{Outcome: "notdone"}
}

// Effects returns a copy of the applied steps, in order.
func (m *Mail) Effects() []Effect {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Effect(nil), m.effects...)
}
