package browser

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Clerk is the browser's only exit (D-139). Each step is checked against its
// key by clerk.Check, then its action line goes to the gate: read{query} for
// an action that cannot change state at the site, post{to, msg} for one that
// may (ADP-14). The gate, not the step, decides which a line needs, so a
// step that claims read for a state change is refused unsent (CLK-3). A post
// is sent only once the key's hold window is over and only while the page
// still shows the role, name and target given in to (CLK-2).
type Clerk struct {
	Name  string
	Owner ed25519.PublicKey
	// Facts, when set, is the clerk's own reading of a step's claims.
	Facts clerk.Facts

	g    *Gate
	mu   sync.Mutex
	done map[string]kernel.Result
}

// NewClerk returns the clerk for one gate.
func NewClerk(name string, owner ed25519.PublicKey, g *Gate) *Clerk {
	return &Clerk{Name: name, Owner: owner, g: g, done: map[string]kernel.Result{}}
}

// Do runs a step at most once per Idem (KRN-8). A post written to the driver
// is remembered whatever its answer, so a redo never sends it again.
func (c *Clerk) Do(r kernel.Request, v kernel.View) kernel.Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	if res, ok := c.done[r.Idem]; ok {
		return res
	}
	if rf := clerk.Check(c.Owner, c.Name, c.Facts, r, v); rf != nil {
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	var line, to string
	post := false
	switch r.Step.Verb {
	case key.Read:
		line = r.Step.Args["query"].Value
	case key.Post:
		line, to, post = r.Step.Args["msg"].Value, r.Step.Args["to"].Value, true
	default:
		return kernel.Result{Outcome: "failed", Detail: "verb"}
	}
	res, how := c.g.do(context.Background(), []byte(line), post, to)
	out := kernel.Result{Outcome: "failed"}
	switch {
	case res.OK:
		out.Outcome = "ok"
	case post && how == lost:
		out.Outcome = "unknown"
	}
	d, _ := json.Marshal(res)
	out.Detail = string(d)
	if post && how != unsent {
		c.done[r.Idem] = out
	}
	return out
}

// Probe reports what this clerk knows without acting. A read is safe to run
// again. A post whose answer was lost is unknown for good: the clerk does not
// read the site to guess, so the kernel parks it for the owner rather than
// sending it twice.
func (c *Clerk) Probe(r kernel.Request, _ kernel.View) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if res, ok := c.done[r.Idem]; ok {
		if res.Outcome == "ok" {
			return "done"
		}
		return "unknown"
	}
	if r.Step.Verb == key.Read {
		return "notdone"
	}
	return "unknown"
}
