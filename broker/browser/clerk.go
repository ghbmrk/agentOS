package browser

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Clerk is the browser's only exit (D-139). Each step is checked against its
// key by clerk.Check, then its query line goes to the gate as a read. The
// gate, not the step, decides whether a line may change state at the site,
// and refuses one that needs the owner's approval unsent: until the owner
// can approve an exact request, no key covers a submit on a session that
// may hold the owner's identity (CLK-3, D-147). A post step is refused for
// the same reason.
type Clerk struct {
	Name  string
	Owner ed25519.PublicKey
	// Clock, when set, is the clerk's own time in unix ms; nil reads the
	// wall clock.
	Clock func() int64

	g    *Gate
	mu   sync.Mutex
	done map[string]bool
}

// NewClerk returns the clerk for one gate.
func NewClerk(name string, owner ed25519.PublicKey, g *Gate) *Clerk {
	return &Clerk{Name: name, Owner: owner, g: g, done: map[string]bool{}}
}

// Do runs a step. A read that cannot change state is safe to run again. One
// that may, sent only because the session is logged out, is an effect: an
// answer lost after it was written is unknown, and one that succeeded is
// remembered as done (KRN-8).
func (c *Clerk) Do(r kernel.Request, v kernel.View) kernel.Result {
	now := time.Now().UnixMilli()
	if c.Clock != nil {
		now = c.Clock()
	}
	if rf := clerk.Check(c.Owner, c.Name, facts, now, r, v); rf != nil {
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	st := step(r)
	if st.Verb != key.Read {
		return kernel.Result{Outcome: "failed", Detail: "approval_required"}
	}
	res, effect, lost := c.g.do(context.Background(), []byte(st.Args["query"].Value))
	out := kernel.Result{Outcome: "failed"}
	switch {
	case res.OK:
		out.Outcome = "ok"
	case lost:
		out.Outcome = "unknown"
	}
	if effect && res.OK {
		c.mu.Lock()
		c.done[stepID(r)] = true
		c.mu.Unlock()
	}
	d, _ := json.Marshal(res)
	out.Detail = string(d)
	return out
}

// Probe reports what the clerk knows without acting. A read that cannot
// change state, and every post (never sent), is notdone. An effect is done
// only if this process saw it succeed; otherwise, on a logged-out session
// where it may have been sent, it is unknown, so the kernel parks it rather
// than sending it twice, after a restart too (KRN-8).
func (c *Clerk) Probe(r kernel.Request, _ kernel.View) string {
	st := step(r)
	if st.Verb != key.Read {
		return "notdone"
	}
	c.mu.Lock()
	done := c.done[stepID(r)]
	c.mu.Unlock()
	switch {
	case done:
		return "done"
	case c.g.cfg.LoggedOut && c.g.effect([]byte(st.Args["query"].Value)):
		return "unknown"
	}
	return "notdone"
}

// stepID names a step of a signed plan.
func stepID(r kernel.Request) string { return r.Plan.ID + "\x00" + strconv.Itoa(r.Index) }

// facts is the clerk's own reading of a step's claims. A read of a page
// moves no money and carries no content class or flow label the clerk can
// vouch for, so a step claiming one is refused (KEY-2).
func facts(key.Step) (string, []string, int64) { return "", nil, 0 }

// step is the step r names, in canonical form; out of range it is the zero
// step, which Check refuses. It is kernel.Request.Step through the opened
// Normalize, since a clerk outside the core calls no other kernel method.
func step(r kernel.Request) key.Step {
	if r.Index < 0 || r.Index >= len(r.Plan.Steps) {
		return key.Step{}
	}
	return kernel.Normalize(r.Plan.ID, r.Plan.Steps[r.Index])
}
