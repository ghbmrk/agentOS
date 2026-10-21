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
// gate sends it once, only if the page is unchanged. Or the owner approved
// the task the key serves, on one site, and the gate sends the task's later
// submits there unless one asks again (CLK-3 one approval per task).
type Clerk struct {
	Name string
	// Anchors are the owner's hardware keys, which every key is checked
	// against (D-146).
	Anchors []ed25519.PublicKey
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
func NewClerk(name string, anchors []ed25519.PublicKey, g *Gate) *Clerk {
	return &Clerk{Name: name, Anchors: anchors, g: g, ran: map[string]ran{}}
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
	st := step(r)
	ver, rf := clerk.Verify(c.Anchors, c.Name, c.facts, now, r, v)
	if rf != nil {
		c.record(id, ran{})
		if msg := []byte(st.Args["msg"].Value); rf.Code == clerk.RClaim && st.Verb == key.Post && st.Content != "" && c.g.print(msg) != st.Content {
			// The post claims a print the page no longer yields: say so,
			// with what approval would cover now (CLK-3).
			return kernel.Result{Outcome: "failed", Detail: logged(c.g.reask(msg))}
		}
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	var res Result
	var rec ran
	switch st.Verb {
	case key.Read:
		res, rec.effect, rec.lost = c.g.do(context.Background(), []byte(st.Args["query"].Value))
	case key.Post:
		// The owner approves this exact print, or the task the key serves
		// on one site (CLK-3, D-147).
		var tc *cover
		if !approval(ver, now) {
			a, ok := kernel.TaskApproved(v, c.Anchors, ver, now)
			if !ok {
				c.record(id, ran{})
				return kernel.Result{Outcome: "failed", Detail: "unapproved"}
			}
			tc = &cover{site: a.Site, first: a.First}
		}
		// A redo of a submit this clerk wrote and did not see succeed is
		// the owner's RETRY: Probe answers unknown for it, so the kernel
		// never redoes it alone, and the owner accepts it may happen twice
		// (KRN-8, CH-11). It sends the print once more.
		c.mu.Lock()
		prev := c.ran[id]
		c.mu.Unlock()
		res, rec.effect, rec.lost = c.g.submit(context.Background(), []byte(st.Args["msg"].Value), st.Args["to"].Value, st.Content, prev.effect && !prev.ok, tc)
		if tc != nil && res.OK && res.Approval != nil {
			res.Covered = coveredLine(*res.Approval, now)
		}
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
	case rec.lost, st.Verb == key.Post && rec.effect:
		// A submit written and not answered ok may have acted (KRN-8).
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

// approval reports whether ver, the plan key as clerk.Verify checked it, is
// the owner's approval of exact submits (CLK-3, OWN-9). Its tip is a link a
// passkey signed for the home clerk itself (key.Narrow), so a compromised
// clerk cannot mint one. That link names the prints and caps the uses
// itself: the key's content set is approval prints only, the link caps its
// uses at their number, and it expires within MaxApproval of now. The set holds each print once, so a print
// listed twice gives no spare use. A passkey cut off since is refused by
// Verify (kernel.Live), and the log's use count keeps each print to one
// send across a restart (KRN-8).
func approval(ver *key.Verified, now int64) bool {
	if ver == nil || !ver.ByOwner {
		return false
	}
	for _, p := range ver.Limits.Content {
		if !strings.HasPrefix(p, printPrefix) {
			return false
		}
	}
	var named, capped, brief bool
	for _, c := range ver.Key.Links[len(ver.Key.Links)-1].Caveats {
		named = named || c.Kind == key.KContent
		capped = capped || c.Kind == key.KUses && c.N <= int64(len(ver.Limits.Content))
		brief = brief || c.Kind == key.KExpires && c.N <= now+MaxApproval
	}
	return named && capped && brief
}

// coveredLine is the fixed-wording STATUS line for a submit a task's
// approval covered: the site, the control's visible label and the time
// sent (CLK-3). Its full fields are the approval beside it in the log.
func coveredLine(a Approval, now int64) string {
	label := a.Label
	if label == "" {
		label = a.Role
	}
	return "Sent on " + a.Site + ": " + label + ", " + time.UnixMilli(now).UTC().Format(time.RFC3339)
}

// MaxApproval bounds how long an approval may live, in ms: one task's
// submits, not a standing permission (D-147).
const MaxApproval = 15 * 60 * 1000

// MaxDetail bounds a step's logged result. The snapshot and the approval
// are bounded where the gate makes them (post, approval), and logged bounds
// every other field, so the whole result, JSON-escaped, fits. If it still
// did not, the snapshot and the approval are dropped and the result says so.
const MaxDetail = 1 << 20

func logged(res Result) string {
	res = small(res)
	d, _ := json.Marshal(res)
	if len(d) > MaxDetail {
		res.Snapshot, res.Approval, res.Truncated = "[result too large]", nil, true
		d, _ = json.Marshal(small(res))
	}
	return string(d)
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
