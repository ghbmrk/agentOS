package browser

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Clerk is the browser's only exit (D-139). Each step is checked against its
// key by clerk.Check, then its query line goes to the gate as a read. The
// gate, not the step, decides whether a line may change state at the site,
// and refuses one that may unsent (approval_required): until the owner can
// approve an exact request, no key covers a submit (CLK-3). A post step is
// refused for the same reason.
type Clerk struct {
	Name  string
	Owner ed25519.PublicKey
	// Clock, when set, is the clerk's own time in unix ms; nil reads the
	// wall clock.
	Clock func() int64

	g *Gate
}

// NewClerk returns the clerk for one gate.
func NewClerk(name string, owner ed25519.PublicKey, g *Gate) *Clerk {
	return &Clerk{Name: name, Owner: owner, g: g}
}

// Do runs a step. Only reads reach the site, and a read is safe to run
// again, so the clerk keeps no memory of what it ran (KRN-8).
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
	res := c.g.do(context.Background(), []byte(st.Args["query"].Value))
	out := kernel.Result{Outcome: "failed"}
	if res.OK {
		out.Outcome = "ok"
	}
	d, _ := json.Marshal(res)
	out.Detail = string(d)
	return out
}

// Probe reports that a step is not done: every step the clerk sends is a
// read, safe to run again, and a refused one was never sent.
func (c *Clerk) Probe(kernel.Request, kernel.View) string { return "notdone" }

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
