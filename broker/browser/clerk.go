package browser

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Clerk is the browser's only exit (D-139). Each step is checked against its
// key by clerk.Check, then its line goes to the gate. A read is sent only if
// the gate judges it needs no approval; one that does is refused unsent with
// the Approval the owner would give (CLK-3, D-147). A post is that approved
// action: its content claims the approval's print, the clerk's facts rebuild
// the print from the page, so only a key for that print covers it, and the
// gate sends it once, only if the page is unchanged.
type Clerk struct {
	Name  string
	Owner ed25519.PublicKey
	// Clock, when set, is the clerk's own time in unix ms; nil reads the
	// wall clock.
	Clock func() int64

	g   *Gate
	mu  sync.Mutex
	ran map[string]ran
}

// ran is what Do judged and saw of a step in this process.
type ran struct {
	// effect: the step may change state at the site and was written.
	effect bool
	// ok: the driver answered it ok; lost: the executor stopped after the
	// write, so whether it acted is unknown.
	ok, lost bool
}

// NewClerk returns the clerk for one gate.
func NewClerk(name string, owner ed25519.PublicKey, g *Gate) *Clerk {
	return &Clerk{Name: name, Owner: owner, g: g, ran: map[string]ran{}}
}

// Do runs a step. A read that cannot change state is safe to run again. A
// post, and a read that may change state sent only because the session is
// logged out, are effects: an answer lost after the write is unknown, and
// Probe answers from what Do saw (KRN-8).
func (c *Clerk) Do(r kernel.Request, v kernel.View) kernel.Result {
	now := time.Now().UnixMilli()
	if c.Clock != nil {
		now = c.Clock()
	}
	id := stepID(r)
	if rf := clerk.Check(c.Owner, c.Name, c.facts, now, r, v); rf != nil {
		c.record(id, ran{})
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	st := step(r)
	var res Result
	var rec ran
	switch st.Verb {
	case key.Read:
		res, rec.effect, rec.lost = c.g.do(context.Background(), []byte(st.Args["query"].Value))
	case key.Post:
		if !approval(r.Plan.Key, c.Owner) {
			c.record(id, ran{})
			return kernel.Result{Outcome: "failed", Detail: "unapproved"}
		}
		res, rec.effect, rec.lost = c.g.submit(context.Background(), []byte(st.Args["msg"].Value), st.Args["to"].Value, st.Content)
	default:
		c.record(id, ran{})
		return kernel.Result{Outcome: "failed", Detail: "verb"}
	}
	rec.ok = res.OK
	c.record(id, rec)
	out := kernel.Result{Outcome: "failed", Detail: logged(res)}
	switch {
	case res.OK:
		out.Outcome = "ok"
	case rec.lost:
		out.Outcome = "unknown"
	}
	return out
}

// record keeps what Do saw of step id. A refusal never replaces an earlier
// write's record: a redo refused unsent leaves the first answer standing.
func (c *Clerk) record(id string, r ran) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.ran[id]; ok && old.effect && !r.effect {
		return
	}
	c.ran[id] = r
}

// Probe reports what the clerk knows without acting, from what Do saw in
// this process, never from the page as it is now. An effect is done if Do
// saw it succeed and unknown otherwise; a step Do sent as a plain read, or
// refused unsent, is notdone. With no record, as after a restart, a post
// is unknown, and so, on a logged-out session, is any read that may have
// acted: the kernel parks them rather than sending them twice (KRN-8).
func (c *Clerk) Probe(r kernel.Request, _ kernel.View) string {
	st := step(r)
	c.mu.Lock()
	rec, ok := c.ran[stepID(r)]
	c.mu.Unlock()
	switch {
	case ok && rec.effect && rec.ok:
		return "done"
	case ok && rec.effect:
		return "unknown"
	case ok:
		return "notdone"
	case st.Verb == key.Post:
		return "unknown"
	case st.Verb == key.Read && c.g.cfg.LoggedOut && c.g.mayAct([]byte(st.Args["query"].Value)):
		return "unknown"
	}
	return "notdone"
}

// facts is the clerk's own reading of a step's claims. A read of a page
// moves no money and carries no content class or flow label the clerk can
// vouch for. A post's content is the print of the approval the gate would
// ask for its action now, so only a key for that print covers it (KEY-2,
// CLK-3).
func (c *Clerk) facts(s key.Step) (string, []string, int64) {
	if s.Verb != key.Post {
		return "", nil, 0
	}
	return c.g.print([]byte(s.Args["msg"].Value)), nil, 0
}

// approval reports whether k is an owner's approval of exact submits: its
// content set lists approval prints only, and its uses are capped at their
// number. No standing key covers a submit (CLK-3), and the log's use count
// keeps each print to one send across a restart (KRN-8).
func approval(k key.Key, owner ed25519.PublicKey) bool {
	v, err := key.Chain(k, owner)
	if err != nil || len(v.Limits.Content) == 0 {
		return false
	}
	for _, p := range v.Limits.Content {
		if !strings.HasPrefix(p, printPrefix) {
			return false
		}
	}
	for _, c := range v.Limits.Caps {
		if c.Kind == key.KUses && c.N <= int64(len(v.Limits.Content)) {
			return true
		}
	}
	return false
}

// MaxDetail bounds a step's logged result. The snapshot is the only large
// field; one whose escaped form would pass the bound is cut further.
const MaxDetail = MaxSnapshot + 64<<10

func logged(res Result) string {
	for {
		d, _ := json.Marshal(res)
		if len(d) <= MaxDetail || res.Snapshot == "" {
			return string(d)
		}
		res.Snapshot, res.Truncated = capText(res.Snapshot, len(res.Snapshot)/2), true
	}
}

// stepID names a step of a signed plan.
func stepID(r kernel.Request) string { return r.Plan.ID + "\x00" + strconv.Itoa(r.Index) }

// step is the step r names, in canonical form; out of range it is the zero
// step, which Check refuses. It is kernel.Request.Step through the opened
// Normalize, since a clerk outside the core calls no other kernel method.
func step(r kernel.Request) key.Step {
	if r.Index < 0 || r.Index >= len(r.Plan.Steps) {
		return key.Step{}
	}
	return kernel.Normalize(r.Plan.ID, r.Plan.Steps[r.Index])
}
