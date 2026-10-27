// Package followclerk is the follow clerk (UPD-2, UPD-8, CH-10, KRN-4): it
// runs the owner's approved switch of update root through follow.Executor.
// It is apart from package follow so agentosd, which serves the page's
// Describe, links none of broker/clerk's network exit (TestAgentosdLinks-
// NoInference).
package followclerk

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/follow"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
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

// Records is the file in the clerk's directory that holds, for each switch
// it started and has not answered, what the box followed just before.
const Records = "follow-steps.json"

// Refusal details beside clerk.Check's codes.
const (
	RVerb      = "verb"      // the step is not change-account
	ROwner     = "owner"     // the plan is not the owner's own approval of this switch
	RMalformed = "malformed" // the digest or the name is not one the clerk takes
	RRecord    = "record"    // the clerk could not read the box or record the step, so did nothing
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
	// dir holds Records, this uid's own.
	dir string
	// mu orders Do and Probe, so a probe never reads a step half begun.
	mu sync.Mutex
}

// before is what the box followed just before a step's switch began.
type before struct {
	Digest string `json:"digest"`
	Name   string `json:"name"`
}

// New is the clerk over x for the owner's anchors, keeping its records in
// dir, a directory that is this uid's alone.
func New(x *follow.Executor, anchors []key.PublicKey, dir string) (*Clerk, error) {
	if err := privfile.Check(dir, true); err != nil {
		return nil, err
	}
	c := &Clerk{x: x, anchors: anchors, dir: dir}
	if _, err := c.records(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Clerk) records() (map[string]before, error) {
	b, err := os.ReadFile(filepath.Join(c.dir, Records))
	if errors.Is(err, os.ErrNotExist) {
		return map[string]before{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]before{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// record makes b idem's record and drops every other step's, or with b
// nil drops idem's, on disk before it returns. A switch beginning drops
// the records of the switches begun before it: once the box may have
// moved again, what it followed before an earlier switch no longer tells
// whether that switch landed (it may have landed and been switched back,
// security 1 round 2 on #3444), so the earlier step can only be unknown.
func (c *Clerk) record(idem string, b *before) error {
	m, err := c.records()
	if err != nil {
		return err
	}
	if b == nil {
		if _, ok := m[idem]; !ok {
			return nil
		}
		delete(m, idem)
	} else {
		m = map[string]before{idem: *b}
	}
	out, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return privfile.WriteAtomic(c.dir, Records, out, nil)
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
	if rf := clerk.Check(c.anchors, Name, c.Facts, c.x.Latest(ctx).UnixMilli(), r, v); rf != nil {
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
	idem := stepID(r)
	if s, ev := c.x.Settled(digest, name); s == follow.SwitchedOK {
		_ = c.record(idem, nil)
		return kernel.Result{Outcome: "ok", Detail: "already: " + ev}
	}
	// What the box follows now is recorded before the switch begins, so a
	// probe can tell a switch that never landed from one a later switch
	// replaced (KRN-8).
	d, n, err := c.x.Current()
	if err == nil {
		err = c.record(idem, &before{d, n})
	}
	if err != nil {
		return kernel.Result{Outcome: "failed", Detail: RRecord}
	}
	s, ev := c.x.Switch(ctx, digest, name)
	if s == follow.SwitchedUnknown {
		return kernel.Result{Outcome: "unknown", Detail: ev}
	}
	// A definite answer needs no record: if it is lost, the probe finds
	// the switch in place, or answers unknown.
	_ = c.record(idem, nil)
	if s == follow.SwitchedOK {
		return kernel.Result{Outcome: "ok", Detail: ev}
	}
	return kernel.Result{Outcome: "failed", Detail: ev}
}

// Probe answers from the box's own trusted root and source and the
// clerk's record of the step, never from what this process held, so it
// answers the same after a restart. Done when the box follows the step's
// root under its name, and the owner is alerted again (at least once,
// OWN-4: the alert of a switch whose answer was lost may never have gone
// out). Notdone only when the record shows the box still follows what it
// did just before this step's switch began, so the switch never landed.
// Anything else is unknown: a switch with no record, or a box that has
// moved on, may have landed and been replaced by a later switch the owner
// approved, and running it again would undo that choice.
func (c *Clerk) Probe(r kernel.Request, _ kernel.View) kernel.Result {
	st := step(r)
	if st.Clerk != Name || st.Verb != key.ChangeAccount {
		return kernel.Result{Outcome: "unknown", Detail: RVerb}
	}
	digest := st.Args[ArgRoot].Value
	name, _ := nameOf(st.Args[ArgName].Value)
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ev := c.x.Settled(digest, name); s == follow.SwitchedOK {
		_ = c.record(stepID(r), nil)
		return kernel.Result{Outcome: "done", Detail: ev + c.x.Realert(context.Background(), name)}
	}
	m, err := c.records()
	if err != nil {
		return kernel.Result{Outcome: "unknown", Detail: RRecord}
	}
	b, ok := m[stepID(r)]
	if !ok {
		return kernel.Result{Outcome: "unknown", Detail: "no record of this switch beginning"}
	}
	d, n, err := c.x.Current()
	if err != nil || d != b.Digest || n != b.Name {
		return kernel.Result{Outcome: "unknown", Detail: "the box no longer follows what it did before this switch"}
	}
	return kernel.Result{Outcome: "notdone", Detail: "the box still follows what it did before this switch"}
}

// stepID keys a step's record: its plan and index, as the kernel's
// idempotency key does (kernel.Request.Idem is not open to a clerk outside
// the core).
func stepID(r kernel.Request) string { return r.Plan.ID + "\x00" + strconv.Itoa(r.Index) }

// step is the request's step as clerk.Check reads it, through the core's
// open kernel.Normalize.
func step(r kernel.Request) key.Step {
	if r.Index < 0 || r.Index >= len(r.Plan.Steps) {
		return key.Step{}
	}
	return kernel.Normalize(key.ChargeTask(r.Plan.Key, r.Plan.ID), r.Plan.Steps[r.Index])
}
