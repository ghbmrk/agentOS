// Package grants holds the broker's authority over effects (PLAN P2,
// grants and approval policy): grants that connect an account's adapter
// (OP-5, ADP-1, ADP-2), owner pre-allowances (ADP-9, ADP-11), and the
// policy that lets an effect run only under one of them or an owner
// approval (REV-2, CH-10, CH-13).
//
// Grants are intents on the broker account (OP-5). Their state is rebuilt
// from the journal on every start: one audit trail, one recovery rule.
//
// The package is on the control path (the daemon imports it), so it may
// not reach a network client or a model (ARC-2). Adapters reach it only
// through the Verifier interface, which the daemon is handed.
package grants

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/verb"
)

// ExecutorName is the executor of the broker-state intents this package
// runs: new grants, pause, and revoke.
const ExecutorName = "grants"

// OriginOwner is the origin of intents the owner's own words start (a
// PAUSE or REVOKE text). Guests' origins are "guest:<lineage>", so no
// guest can submit one.
const OriginOwner = "owner"

// Params keys a pre-allowed intent may carry besides the rule's fixed
// params: the source record it acts on, and for a context-scoped reply
// (ADP-11) the reply's body. Nothing else, so there is no free text
// (ADP-9: templated content only).
const (
	ParamRecord = "record"
	ParamBody   = "body"
)

// Spec is what a grant intent (journal.ActionGrantChange) asks for, in its
// params under "grant". Exactly one of three shapes:
//
//   - an adapter grant: Account, Executor, and Ops, the operations the
//     owner accepts and the verb each maps to (ADP-1, ADP-2). An operation
//     not listed does not exist for agents.
//   - a pre-allowance: Account and Rule (ADP-9, ADP-11).
//   - Resume: the ID of a paused grant to restore.
//
// Every shape is a new or wider grant: high-tier code plus local
// confirmation (CH-3, CH-10).
type Spec struct {
	Account  string            `json:"account,omitempty"`
	Executor string            `json:"executor,omitempty"`
	Ops      map[string]string `json:"ops,omitempty"`
	Rule     *Rule             `json:"rule,omitempty"`
	Resume   string            `json:"resume,omitempty"`
}

// Rule is an owner pre-allowance (ADP-9): a deterministic predicate the
// broker checks against fields it read from the source system, never the
// agent's claims.
type Rule struct {
	// Action is the one operation covered; the account's adapter grant
	// must map it to an irreversible verb other than reveal-or-create-secret
	// (CRED-6 keeps per-action approval).
	Action string `json:"action"`
	// Params are fixed by the owner, e.g. the template to fill. A covered
	// intent carries exactly these plus ParamRecord (and ParamBody for a
	// reply rule).
	Params map[string]string `json:"params,omitempty"`
	// Recipients, if set, are the only recipients allowed; either way the
	// recipients must be the ones the source record names.
	Recipients []string `json:"recipients,omitempty"`
	// AmountCap is the largest amount, in the account's minor units, that
	// may move. Zero: an operation that moves money never matches.
	AmountCap int64 `json:"amount_cap,omitempty"`
	// Scope bounds, required in every rule: runs per source record per
	// day, and runs per day.
	PerRecord int `json:"per_record"`
	PerDay    int `json:"per_day"`
	// HoldDays: a record edited in the last N days does not match (§17
	// risk 8). Zero: no hold.
	HoldDays int `json:"hold_days,omitempty"`
	// Reply makes this an ADP-11 context-scoped reply rule: free-text
	// replies within existing threads, alerted with an undo window.
	Reply bool `json:"reply,omitempty"`
}

// Grant is a live grant: an adapter grant or a pre-allowance.
type Grant struct {
	ID     string
	Spec   Spec
	Paused bool
}

// parseSpec reads a grant intent's spec strictly: unknown fields are an
// error, so nothing in the params is silently ignored.
func parseSpec(in journal.Intent) (Spec, error) {
	raw, ok := in.Params["grant"]
	if !ok || len(in.Params) != 1 {
		return Spec{}, errors.New("a grant intent carries exactly one param, grant")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return Spec{}, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var s Spec
	if err := d.Decode(&s); err != nil {
		return Spec{}, fmt.Errorf("grant spec: %v", err)
	}
	return s, nil
}

// validateLocked checks a spec against the live grants.
func (g *Gate) validateLocked(s Spec) error {
	shapes := 0
	for _, set := range []bool{s.Executor != "" || len(s.Ops) > 0, s.Rule != nil, s.Resume != ""} {
		if set {
			shapes++
		}
	}
	if shapes != 1 {
		return errors.New("a grant is exactly one of: an adapter grant, a pre-allowance, or a resume")
	}
	if s.Resume != "" {
		gr := g.grants[s.Resume]
		if gr == nil || !gr.Paused || s.Account != "" {
			return fmt.Errorf("no paused grant %s", clip(s.Resume))
		}
		return nil
	}
	if s.Account == "" || s.Account == journal.BrokerAccount {
		return errors.New("a grant names an external account")
	}
	if s.Rule == nil {
		if s.Executor == ExecutorName || !g.executors[s.Executor] {
			return fmt.Errorf("executor %q is not a connected adapter", clip(s.Executor))
		}
		if len(s.Ops) == 0 {
			return errors.New("an adapter grant declares at least one operation")
		}
		for op, v := range s.Ops {
			if op == "" || !verb.Valid(v) {
				return fmt.Errorf("operation %q: verb %q is not on the broker's list (ADP-2)", clip(op), clip(v))
			}
		}
		return nil
	}
	r := s.Rule
	ag := g.adapterLocked(s.Account)
	if ag == nil {
		return fmt.Errorf("no adapter grant connects %s", clip(s.Account))
	}
	v, ok := ag.Spec.Ops[r.Action]
	if !ok {
		return fmt.Errorf("operation %q is not declared for %s", clip(r.Action), clip(s.Account))
	}
	switch c, _ := verb.ClassOf(v); c {
	case verb.Reversible:
		return fmt.Errorf("%s is %s, which needs no pre-allowance", clip(r.Action), v)
	case verb.Secret:
		return errors.New("reveal-or-create-secret keeps per-action approval under any rule (CRED-6)")
	}
	if r.PerRecord < 1 || r.PerDay < 1 || r.AmountCap < 0 || r.HoldDays < 0 {
		return errors.New("every rule has scope bounds: per_record and per_day of at least 1 (ADP-9)")
	}
	if r.Reply && (v != verb.Send || r.AmountCap != 0) {
		return errors.New("a reply rule covers a send that moves no money (ADP-11)")
	}
	for k := range r.Params {
		if k == ParamRecord || k == ParamBody {
			return fmt.Errorf("param %q is filled per run, not fixed by the rule", k)
		}
	}
	return nil
}

// Describe renders a spec in fixed wording for the owner (ADP-9:
// fixed-wording approval). The local confirmation page shows it in full;
// the approval text carries the short form.
func Describe(s Spec) string {
	switch {
	case s.Resume != "":
		return fmt.Sprintf("Resume grant %s.", s.Resume)
	case s.Rule == nil:
		ops := make([]string, 0, len(s.Ops))
		for op, v := range s.Ops {
			ops = append(ops, op+" ("+v+")")
		}
		sort.Strings(ops)
		return fmt.Sprintf("Connect account %s through %s, allowing: %s. Reads and drafts run freely; every other verb needs your approval or a pre-allowance.",
			s.Account, s.Executor, strings.Join(ops, ", "))
	}
	r := s.Rule
	var b strings.Builder
	if r.Reply {
		fmt.Fprintf(&b, "Let the agent reply in existing threads on %s (%s) without asking, to the thread's own participants only. Each reply is texted to you first and sends after the undo window unless you reply UNDO.", s.Account, r.Action)
	} else {
		fmt.Fprintf(&b, "Let %s on %s run without asking or notifying you, when every field comes from the source record.", r.Action, s.Account)
	}
	if len(r.Params) > 0 {
		ks := make([]string, 0, len(r.Params))
		for k, v := range r.Params {
			ks = append(ks, k+"="+v)
		}
		sort.Strings(ks)
		fmt.Fprintf(&b, " Fixed: %s.", strings.Join(ks, ", "))
	}
	if len(r.Recipients) > 0 {
		fmt.Fprintf(&b, " Only to: %s.", strings.Join(r.Recipients, ", "))
	}
	if r.AmountCap > 0 {
		fmt.Fprintf(&b, " Amounts up to %s.", minor(r.AmountCap))
	} else {
		b.WriteString(" No money may move.")
	}
	fmt.Fprintf(&b, " At most %d per record and %d per day.", r.PerRecord, r.PerDay)
	if r.HoldDays > 0 {
		fmt.Fprintf(&b, " Records edited in the last %d days need your approval.", r.HoldDays)
	}
	b.WriteString(" Text PAUSE or REVOKE and its ID to stop it.")
	return b.String()
}

// short is the approval text's object for a grant (CH-12 keeps it to one
// line; the local page shows Describe).
func short(s Spec) string {
	switch {
	case s.Resume != "":
		return "resume " + s.Resume
	case s.Rule == nil:
		vs := map[string]bool{}
		for _, v := range s.Ops {
			vs[v] = true
		}
		var l []string
		for v := range vs {
			l = append(l, v)
		}
		sort.Strings(l)
		return "connect " + s.Account + ": " + strings.Join(l, " ")
	case s.Rule.Reply:
		return fmt.Sprintf("auto-replies on %s, %d/day", s.Account, s.Rule.PerDay)
	}
	return fmt.Sprintf("pre-allow %s on %s, %d/day", s.Rule.Action, s.Account, s.Rule.PerDay)
}

func minor(n int64) string { return fmt.Sprintf("%d.%02d", n/100, n%100) }

func clip(s string) string {
	if len(s) > 64 {
		return s[:64] + "..."
	}
	return s
}
