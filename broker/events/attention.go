package events

import (
	"sort"
	"sync"
)

// Origin says who started the work a notice is about.
type Origin string

const (
	// Background work was started by an event or a timer (CAP-4). It is
	// the zero value, so an unmarked notice gets the paced rule.
	Background Origin = ""
	// OwnerRequest work was asked for by the owner, who is waiting on it in
	// the conversation.
	OwnerRequest Origin = "owner"
)

// Notice is something the owner might be told.
type Notice struct {
	Text   string
	Origin Origin
	// Decision is true when the owner must decide (an approval request).
	Decision bool
	// Irreversible is true when the decision is about an irreversible or
	// external effect (REV-2). Reversible work never asks.
	Irreversible bool
	// Class is the notice's urgency class key; the owner defines which
	// classes are urgent (CH-15).
	Class string
}

// Route says how a notice reaches the owner.
type Route int

const (
	// Digest: listed in the next daily digest; no text now.
	Digest Route = iota
	// Batch: an irreversible decision, numbered into the next batched
	// approval request (CH-13), sent with the digest.
	Batch
	// Interrupt: an urgent irreversible decision, sent now.
	Interrupt
	// Conversation: about work the owner asked for; answered in the
	// conversation now (decisions, results and failures alike).
	Conversation
)

func (r Route) String() string {
	return [...]string{"digest", "batch", "interrupt", "conversation"}[r]
}

// Attention applies CAP-4's interruption rule to background work (started
// by events and timers): only irreversible decisions interrupt, and they are
// batched into the digest unless their class is one the owner marked urgent.
// Events, results and failures of background work never interrupt, whatever
// their class. Work the owner asked for is not an interruption: its
// decisions, results and failures go to the conversation at once. Pacing and
// quiet hours (CH-15) are the owner channel's job downstream.
type Attention struct {
	mu        sync.Mutex
	urgent    map[string]bool
	notes     []string
	decisions []Notice
}

// NewAttention returns an Attention with the owner's urgent classes.
func NewAttention(urgent ...string) *Attention {
	a := &Attention{}
	a.SetUrgent(urgent)
	return a
}

// SetUrgent replaces the owner-defined urgent classes. Callers must take
// these only from an authenticated owner setting.
func (a *Attention) SetUrgent(classes []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.urgent = map[string]bool{}
	for _, c := range classes {
		a.urgent[c] = true
	}
}

// Route classifies a notice without recording it.
func (a *Attention) Route(n Notice) Route {
	if n.Origin == OwnerRequest {
		return Conversation
	}
	if !n.Decision || !n.Irreversible {
		return Digest
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if n.Class != "" && a.urgent[n.Class] {
		return Interrupt
	}
	return Batch
}

// Submit routes a notice. Digest and Batch notices are kept for TakeDigest;
// for Interrupt and Conversation the caller sends the notice now.
func (a *Attention) Submit(n Notice) Route {
	r := a.Route(n)
	a.mu.Lock()
	defer a.mu.Unlock()
	switch r {
	case Digest:
		a.notes = append(a.notes, n.Text)
	case Batch:
		a.decisions = append(a.decisions, n)
	}
	return r
}

// Note adds an informational digest line.
func (a *Attention) Note(text string) { a.Submit(Notice{Text: text}) }

// TakeDigest returns and clears the digest lines and the batched decisions.
func (a *Attention) TakeDigest() (notes []string, decisions []Notice) {
	a.mu.Lock()
	defer a.mu.Unlock()
	notes, decisions = a.notes, a.decisions
	a.notes, a.decisions = nil, nil
	return notes, decisions
}

// UrgentClasses lists the owner's urgent classes, sorted.
func (a *Attention) UrgentClasses() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.urgent))
	for c := range a.urgent {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
