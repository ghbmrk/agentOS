package guest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"time"

	"github.com/ghbmrk/agentos/broker/guesterr"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Kernel is the part of the kernel's owner seam the plane submits plans on
// (PLN-5 (b)). agentosd's is its client of the kernel's owner socket
// (owner/kernelsock); a plan's authority is its key and the signature of the
// key's last holder, never the channel it came on (KEY-1, KEY-3).
type Kernel interface {
	// Submit logs p and has the kernel decide it at once.
	Submit(ctx context.Context, p kernel.Plan) error
	// Plan is plan id's status and its steps' phases; ok is false when the
	// log holds no such plan.
	Plan(ctx context.Context, id string) (status string, phases []string, ok bool, err error)
}

// Keys returns the key machine's plans run under and the private key of its
// last holder, with which the plane signs each plan, so the guest holds no
// credential (PLN-5, KEY-3). ok is false when no key is granted for it.
type Keys func(machine string) (k key.Key, holder ed25519.PrivateKey, ok bool)

// planState is what a guest learns about its plan: the kernel's status and
// its steps' phases, never a clerk's evidence.
type planState struct {
	RequestID string   `json:"request_id"`
	State     string   `json:"state"`
	Phases    []string `json:"phases,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

type planArgs struct {
	RequestID string     `json:"request_id"`
	Steps     []planStep `json:"steps"`
}

type planStep struct {
	Verb    string            `json:"verb"`
	Clerk   string            `json:"clerk"`
	Args    map[string]string `json:"args"`
	Content string            `json:"content"`
	Labels  []string          `json:"labels"`
}

// Bounds on one plan's guest-chosen fields.
const (
	maxSteps     = 16
	maxPlanBytes = 16 << 10
	maxLabels    = 8
)

// The guest's fixed texts for a plan that did not run.
const (
	reasonNoKernel = "the kernel is not reached yet; nothing was submitted. Repeat plan with the same request_id later"
	reasonNoKey    = "no key is granted to this machine yet, so no plan can run; the owner grants keys (KEY-4)"
	reasonRejected = "the kernel rejected this plan (its key check, or a STOP in force), and no step ran; a reworded plan is not tried again (PLN-4)"
	reasonRepeat   = "this request_id was used before; nothing new was submitted, and this is that plan's state"
	reasonLost     = "the kernel did not answer; repeat plan with the same request_id to learn whether it was taken"
)

// callTool runs the plan command for machine m, and reports whether a plan
// went to the kernel. Plan IDs are the machine's fork lineage: forks share
// their source's memory, so a plan a fork repeats from its source's history
// is the same plan and runs at most once, while no machine outside the
// lineage can read or collide with it. Errors the guest sees are fixed
// strings; broker detail goes to Logf.
func (p *Plane) callTool(ctx context.Context, m *machine, name string, raw json.RawMessage) (planState, bool, error) {
	lineage := p.lineageOf(m)
	if lineage == "" {
		return planState{}, false, guesterr.New("broker: unknown machine")
	}
	if name != PlanTool {
		return planState{}, false, guesterr.Newf("no tool %q", guesterr.Guest(clip(name, 64)))
	}
	var a planArgs
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&a); err != nil {
		return planState{}, false, guesterr.New("arguments must be an object")
	}
	if !requestIDRE.MatchString(a.RequestID) {
		return planState{}, false, guesterr.New("request_id (letters, digits, . _ -; at most 64) is required")
	}
	if err := checkSteps(a.Steps); err != nil {
		return planState{}, false, err
	}
	if p.cfg.Kernel == nil {
		return planState{RequestID: a.RequestID, State: "refused", Reason: reasonNoKernel}, false, nil
	}
	label := p.label(m.id)
	id, prior, seen, err := p.planID(ctx, lineage, a.RequestID, label)
	if err != nil {
		p.cfg.Logf("guest %s: plan %s: read: %v", m.id, a.RequestID, err)
		return planState{RequestID: a.RequestID, State: "unknown", Reason: reasonLost}, false, nil
	}
	if seen {
		// A repeat reads the plan; it never submits again (KRN-5). A
		// private machine repeating one its lineage made while public sees
		// it but drives nothing, so nothing a private machine does changes
		// what a public one can observe (REV-5).
		st := prior
		st.RequestID = a.RequestID
		if len(a.Steps) > 0 {
			st.Reason = joinReason(reasonRepeat, st.Reason)
		}
		return st, false, nil
	}
	if len(a.Steps) == 0 {
		return planState{}, false, guesterr.Newf("no plan %s; a first plan needs steps", guesterr.Guest(a.RequestID))
	}
	if !m.rate.take(p.cfg.SubmitBurst, p.cfg.SubmitEvery) {
		return planState{}, false, guesterr.New("too many plans from this machine; wait and repeat with the same request_id")
	}
	var k key.Key
	var holder ed25519.PrivateKey
	ok := false
	if p.cfg.Keys != nil {
		k, holder, ok = p.cfg.Keys(m.id)
	}
	if !ok {
		return planState{RequestID: a.RequestID, State: "refused", Reason: reasonNoKey}, false, nil
	}
	plan := kernel.SignPlan(kernel.Plan{ID: id, Key: k, Steps: steps(a.Steps, label)}, holder)
	// The plan is taken to its decision even if the guest hangs up.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	serr := p.cfg.Kernel.Submit(sctx, plan)
	st, found, rerr := p.read(sctx, id)
	switch {
	case rerr != nil:
		p.cfg.Logf("guest %s: plan %s: submit: %v; read: %v", m.id, id, serr, rerr)
		return planState{RequestID: a.RequestID, State: "unknown", Reason: reasonLost}, true, nil
	case !found:
		// Not in the log: the kernel refused it before logging it (a
		// malformed plan, STOP's refusal) or never got it.
		p.cfg.Logf("guest %s: plan %s: submit: %v", m.id, id, serr)
		return planState{RequestID: a.RequestID, State: "refused", Reason: "the kernel did not take this plan; nothing ran"}, serr != nil, nil
	}
	if serr != nil {
		// Logged all the same: an answer lost after the kernel took it, or
		// a concurrent first submission of the same plan.
		p.cfg.Logf("guest %s: plan %s: submit: %v (the log holds it)", m.id, id, serr)
	}
	st.RequestID = a.RequestID
	return st, true, nil
}

// checkSteps bounds a plan's steps before anything is signed or sent.
func checkSteps(ss []planStep) error {
	if len(ss) > maxSteps {
		return guesterr.Newf("more than %d steps", guesterr.Num(maxSteps))
	}
	if b, _ := json.Marshal(ss); len(b) > maxPlanBytes {
		return guesterr.Newf("the steps are larger than %d bytes", guesterr.Num(maxPlanBytes))
	}
	for _, s := range ss {
		if !nameRE.MatchString(s.Verb) || !nameRE.MatchString(s.Clerk) {
			return guesterr.New("each step needs a verb and a clerk, lowercase names (a-z, 0-9, . _ -; at most 64)")
		}
		if len(s.Labels) > maxLabels {
			return guesterr.Newf("a step has more than %d labels", guesterr.Num(maxLabels))
		}
		for _, l := range s.Labels {
			if !nameRE.MatchString(l) {
				return guesterr.New("labels must be lowercase names (a-z, 0-9, . _ -; at most 64)")
			}
		}
	}
	return nil
}

// steps are the guest's steps as the kernel takes them. Every step carries
// the machine's own label besides any the guest claims, so a private
// machine's plan can never pass for public data (PLN-3: labels only
// accumulate).
func steps(ss []planStep, label string) []kernel.PlanStep {
	out := make([]kernel.PlanStep, len(ss))
	for i, s := range ss {
		labels := append([]string(nil), s.Labels...)
		if !slices.Contains(labels, label) {
			labels = append(labels, label)
		}
		slices.Sort(labels)
		args := s.Args
		if args == nil {
			args = map[string]string{}
		}
		out[i] = kernel.PlanStep{Verb: key.Verb(s.Verb), Clerk: s.Clerk, Args: args, Content: s.Content, Labels: labels}
	}
	return out
}

// read is plan id as the guest sees it.
func (p *Plane) read(ctx context.Context, id string) (planState, bool, error) {
	status, phases, ok, err := p.cfg.Kernel.Plan(ctx, id)
	if err != nil || !ok {
		return planState{}, false, err
	}
	st := planState{State: status, Phases: phases}
	if status == kernel.SRejected {
		st.Reason = reasonRejected
	}
	return st, true, nil
}

// label is the machine's data label, failing closed.
func (p *Plane) label(machine string) string {
	if p.cfg.Label != nil {
		if l := p.cfg.Label(machine); l == "public" || l == "private" {
			return l
		}
	}
	return "private"
}

// planID partitions a lineage's plans by data label (REV-5). Public
// machines use <lineage>/<request_id>; private ones
// <lineage>/private/<request_id> (request IDs hold no '/', so the two never
// collide). A public machine never sees, collides with, or learns anything
// from a private machine's plan. A private machine repeating a plan its
// lineage made while public reads that plan; no repeat submits again.
//
// When the kernel's log already holds the plan, prior is its state and seen
// is true.
func (p *Plane) planID(ctx context.Context, lineage, reqID, label string) (id string, prior planState, seen bool, err error) {
	pub := lineage + "/" + reqID
	if label != "private" {
		st, ok, err := p.read(ctx, pub)
		return pub, st, ok, err
	}
	priv := privateID(lineage, reqID)
	if st, ok, err := p.read(ctx, priv); err != nil || ok {
		return priv, st, ok, err
	}
	if st, ok, err := p.read(ctx, pub); err != nil || ok {
		return pub, st, ok, err
	}
	return priv, planState{}, false, nil
}

func privateID(lineage, reqID string) string { return lineage + "/private/" + reqID }

func joinReason(a, b string) string {
	if b == "" {
		return a
	}
	return a + "; " + b
}
