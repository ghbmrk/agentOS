// Package followclerk is the follow clerk (UPD-2, UPD-8, CH-10, KRN-4): it
// runs the owner's approved switch of update root through follow.Executor.
// It is apart from package follow so agentosd, which serves the page's
// Describe, links none of broker/clerk's network exit (TestAgentosdLinks-
// NoInference).
package followclerk

import (
	"context"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk/check"
	"github.com/ghbmrk/agentos/broker/follow"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Name is the follow clerk's name in a plan step and a key's root.
const Name = "follow"

// A switch of update root is box configuration nobody can undo for the
// owner, so it is change-account, irreversible at the high tier (VRB-2,
// KRN-4). Its object is the digest of the root summary the page showed;
// its value is the owner's name for the source, or ArgProject to switch
// back to the project's own root.
const (
	ArgRoot = "target"
	ArgName = "value"
)

// ArgProject is the value of a switch back to the project's own root. The
// kernel refuses an empty argument (key.ArgsDeclared), and follow.NameOK
// refuses this one as a look-alike of the project's name, so no named
// follow can carry it.
const ArgProject = follow.ProjectName

// Refusal details beside check.Check's codes.
const (
	RVerb      = "verb"      // the step is not change-account
	ROwner     = "owner"     // the plan is not the owner's own approval of this switch
	RMalformed = "malformed" // the digest or the name is not one the clerk takes
)

// Step is the one step that follows the root with this digest under name,
// "" switching back to the project's own root.
func Step(digest, name string) kernel.PlanStep {
	if name == "" {
		name = ArgProject
	}
	return kernel.PlanStep{Verb: key.ChangeAccount, Clerk: Name, Args: map[string]string{ArgRoot: digest, ArgName: name}}
}

// Clerk runs follows on x, the executor the page describes roots on, so it
// switches only to a root the page holds.
type Clerk struct {
	x *follow.Executor
	// anchors are the owner's hardware keys, the clerk's own trust root
	// (D-146).
	anchors []key.PublicKey
	// mu orders Do and Probe, so a probe never reads a switch half made.
	mu sync.Mutex
}

// New is the clerk over x for the owner's anchors.
func New(x *follow.Executor, anchors []key.PublicKey) *Clerk {
	return &Clerk{x: x, anchors: anchors}
}

// nameOf is the follow name a step's value asks for: "" for ArgProject.
func nameOf(value string) (string, bool) {
	if value == ArgProject {
		return "", true
	}
	return value, follow.NameOK(value)
}

// Facts is the clerk's own reading of a step: a switch carries no content
// class or flow label the clerk vouches for, and moves no money (KEY-2;
// change-account has no amount argument).
func (c *Clerk) Facts(key.Step) (string, []string, int64) { return "", nil, 0 }

// Do switches to the held root the step names, once its own checks pass
// (CLK-2): the key against the clerk's anchors on the guard clock's Latest,
// and the plan as the owner's own approval of this exact switch, signed by
// a passkey under a bare root (CH-10's tier 4; no standing key covers it,
// KRN-4). A switch the box already holds is answered ok without switching
// again, so an answer lost after the switch never switches twice (KRN-8).
func (c *Clerk) Do(r kernel.Request, v kernel.View) kernel.Result {
	ctx := context.Background()
	if rf := check.Check(c.anchors, Name, c.Facts, c.x.Latest(ctx).UnixMilli(), r, v); rf != nil {
		return kernel.Result{Outcome: "failed", Detail: rf.Code}
	}
	st := step(r)
	if st.Verb != key.ChangeAccount {
		return kernel.Result{Outcome: "failed", Detail: RVerb}
	}
	if len(r.Plan.Key.Links) != 0 {
		return kernel.Result{Outcome: "failed", Detail: ROwner}
	}
	digest := st.Args[ArgRoot].Value
	name, ok := nameOf(st.Args[ArgName].Value)
	if !follow.DigestOK(digest) || !ok {
		return kernel.Result{Outcome: "failed", Detail: RMalformed}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ev := c.x.Settled(digest, name); s == follow.SwitchedOK {
		return kernel.Result{Outcome: "ok", Detail: "already: " + ev}
	}
	switch s, ev := c.x.Switch(ctx, digest, name); s {
	case follow.SwitchedOK:
		return kernel.Result{Outcome: "ok", Detail: ev}
	case follow.SwitchedUnknown:
		return kernel.Result{Outcome: "unknown", Detail: ev}
	default:
		return kernel.Result{Outcome: "failed", Detail: ev}
	}
}

// Probe answers from the box's own trusted root and source, never from
// what this process held, so it answers the same after a restart: done
// when the box follows the step's root under its name, and the owner is
// alerted again (at least once, OWN-4: the alert of a switch whose answer
// was lost may never have gone out); unknown otherwise, never notdone.
// The kernel fences only an identical step, so a later switch the owner
// approved may have replaced this one, and no reading of the box proves
// this one never landed (three rounds on #3444 each found another order
// that a "not landed" rule got wrong). A step that is not done parks for
// the owner's RETRY (KRN-8) rather than risk undoing a later approval.
func (c *Clerk) Probe(r kernel.Request, _ kernel.View) kernel.Result {
	st := step(r)
	if st.Clerk != Name || st.Verb != key.ChangeAccount {
		return kernel.Result{Outcome: "unknown", Detail: RVerb}
	}
	digest := st.Args[ArgRoot].Value
	name, _ := nameOf(st.Args[ArgName].Value)
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ev := c.x.Settled(digest, name)
	if s != follow.SwitchedOK {
		return kernel.Result{Outcome: "unknown", Detail: ev}
	}
	return kernel.Result{Outcome: "done", Detail: ev + c.x.Realert(context.Background(), name)}
}

// step is the request's step as check.Check reads it, through the core's
// open kernel.Normalize.
func step(r kernel.Request) key.Step {
	if r.Index < 0 || r.Index >= len(r.Plan.Steps) {
		return key.Step{}
	}
	return kernel.Normalize(key.ChargeTask(r.Plan.Key, r.Plan.ID), r.Plan.Steps[r.Index])
}
