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
	"unicode/utf8"

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

// OriginRecall and RecallExecutor mark the broker's recall rollback
// intents (journal.ActionRecallRollback); recalltool submits and runs them.
const (
	OriginRecall   = "broker:recall"
	RecallExecutor = "recall"
)

// OriginLoop2 marks Loop 2's containment (loops S8, K-S2): a pause of a
// grant on a finding, and nothing else. Only the broker submits it; guest
// intents carry "guest:<lineage>".
const OriginLoop2 = "broker:loop2"

// OriginEvidence marks the broker's delivery of an agent reply to the
// owner's evidence destination (CH-20): the only origin the gate allows
// a Config.Delivery operation from, and only for that.
const OriginEvidence = "broker:evidence"

// A delivery's params: the body and who wrote it, the agent or the box
// itself (a notice), so the adapter can label it (security C4 on #148).
const (
	ParamFrom        = "from"
	DeliverFromAgent = "agent"
	DeliverFromBox   = "box"
)

// DeliveryCap bounds deliveries to the evidence destination in any 24
// hours (security C5 on #148); past it a delivery is denied with
// DeliveryCapReason and the broker keeps the reply instead.
const (
	DeliveryCap       = 30
	DeliveryCapReason = "today's emailed replies are used up"
)

// originLocal is the local page's origin.
const originLocal = "local"

// Params of a journal.ActionEvidence intent: the destination address
// (empty clears it) and the account whose own address it is.
const (
	ParamEvidenceAddress = "address"
	ParamEvidenceAccount = "account"
)

// EvidenceIntent is the intent that sets the evidence destination to
// address on account, or clears it when address is empty (CH-20).
func EvidenceIntent(id, origin, address, account string) journal.Intent {
	if address == "" {
		account = ""
	}
	return journal.Intent{ID: id, Origin: origin, Account: journal.BrokerAccount, Action: journal.ActionEvidence,
		Params: map[string]any{ParamEvidenceAddress: address, ParamEvidenceAccount: account}, Executor: ExecutorName}
}

// Params of a journal.ActionUpdateFollow intent: the name the owner gave
// the source, and the digest of the root summary the page showed
// (update.RootSummary.Digest), which the updater follows and nothing else.
const (
	ParamFollowName   = "name"
	ParamFollowDigest = "digest"
	// FollowExecutor is the updater, which runs the switch.
	FollowExecutor = "update"
	// MaxFollowName bounds the owner-typed name, in characters.
	MaxFollowName = 40
)

// FollowIntent is the local page's request to follow the root whose
// summary has digest, under the owner's name for it.
func FollowIntent(id, name, digest string) journal.Intent {
	return journal.Intent{ID: id, Origin: originLocal, Account: journal.BrokerAccount, Action: journal.ActionUpdateFollow,
		Params: map[string]any{ParamFollowName: name, ParamFollowDigest: digest}, Executor: FollowExecutor}
}

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
		declared := g.cfg.Declared[s.Executor]
		if s.Executor == ExecutorName || declared == nil {
			return fmt.Errorf("executor %q is not a connected adapter", clip(s.Executor))
		}
		if len(s.Ops) == 0 {
			return errors.New("an adapter grant chooses at least one operation")
		}
		for op, v := range s.Ops {
			dv, ok := declared[op]
			if !ok {
				return fmt.Errorf("operation %q is not one the adapter declares", clip(op))
			}
			c, ok := verb.ClassOf(v)
			dc, _ := verb.ClassOf(dv)
			if !ok || c < dc {
				// ADP-2: the adapter's mapping is the floor; a grant can
				// only make an operation stricter.
				return fmt.Errorf("operation %q: verb %q is weaker than the adapter's %q or not on the list", clip(op), clip(v), dv)
			}
		}
		for _, x := range g.grants {
			if x.Spec.Rule == nil && x.Spec.Account == s.Account {
				// One connection per account, so policy never depends on
				// which of two grants is found first (OP-5).
				return fmt.Errorf("%s already connects this account; revoke it first", x.ID)
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
		// The text names every operation that acts; reads and drafts are
		// left to the local page's full list.
		var acts []string
		for op, v := range s.Ops {
			if c, ok := verb.ClassOf(v); !ok || c != verb.Reversible {
				acts = append(acts, op)
			}
		}
		sort.Strings(acts)
		o := "connect " + s.Account
		if len(acts) == 0 {
			return o + ", reads and drafts only"
		}
		if l := o + ", acts: " + strings.Join(acts, " "); len(l) <= 40 {
			return l
		}
		return fmt.Sprintf("connect %s, %d acting ops on Wi-Fi page", s.Account, len(acts))
	case s.Rule.Reply:
		return fmt.Sprintf("auto-replies on %s, %d/day", s.Account, s.Rule.PerDay)
	}
	return fmt.Sprintf("pre-allow %s on %s, %d/day", s.Rule.Action, s.Account, s.Rule.PerDay)
}

func minor(n int64) string { return fmt.Sprintf("%d.%02d", n/100, n%100) }

// clip shortens s to at most 64 bytes on a rune boundary.
func clip(s string) string {
	if len(s) <= 64 {
		return s
	}
	n := 64
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}
