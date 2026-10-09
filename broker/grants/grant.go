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

	"github.com/ghbmrk/agentos/broker/guesterr"
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

// OriginForget and ForgetExecutor mark the broker's forget of an owner
// task (journal.ActionLearnForget, W3-forget): agentosd submits it on the
// owner's FORGET and runs it once the owner approves.
const (
	OriginForget   = "broker:forget"
	ForgetExecutor = "forget"
)

// ForgetID is the ID of a forget intent for goal; nonce is unique per ask
// and holds no "/". The goal rides in the ID because the journal keeps
// identifiers as they are while it redacts params (journal.Redactor).
func ForgetID(nonce, goal string) string { return "forget/" + nonce + "/" + goal }

// ForgetGoal is the goal a forget intent's ID names; "" if malformed.
func ForgetGoal(id string) string {
	rest, ok := strings.CutPrefix(id, "forget/")
	if !ok {
		return ""
	}
	nonce, goal, ok := strings.Cut(rest, "/")
	if !ok || nonce == "" {
		return ""
	}
	return goal
}

// ForgetAgentID is the ID of item 2 of the owner's forget request
// (W3-forget-b2b): taking back the agent's work since the task. It shares
// item 1's nonce, so each item can name the other (ForgetSibling).
func ForgetAgentID(nonce, goal string) string { return "forget-agent/" + nonce + "/" + goal }

// ForgetAgentGoal is the goal a take-back intent's ID names; "" if malformed.
func ForgetAgentGoal(id string) string {
	rest, ok := strings.CutPrefix(id, "forget-agent/")
	if !ok {
		return ""
	}
	nonce, goal, ok := strings.Cut(rest, "/")
	if !ok || nonce == "" {
		return ""
	}
	return goal
}

// ForgetAgentActions is item 2's detail from its "actions" param: the
// agent's actions so far, counted when asked, which stay done (CAP-3;
// DECISIONS 2026-10-05), in a recall rollback's words. A count, not text,
// so the journal's redactor leaves it; none or a bad one names nothing.
func ForgetAgentActions(params map[string]any) string {
	var n int64
	switch v := params["actions"].(type) {
	case int:
		n = int64(v)
	case json.Number:
		var err error
		if n, err = v.Int64(); err != nil {
			return ""
		}
	default:
		return ""
	}
	switch {
	case n < 0:
		return ""
	case n == 0:
		return "no actions yet"
	case n == 1:
		return "1 action so far stays done"
	}
	return fmt.Sprintf("%d actions so far stay done", n)
}

// ForgetSibling is the other item of the request id belongs to: the
// take-back for a forget, the forget for a take-back; "" if malformed.
func ForgetSibling(id string) string {
	if rest, ok := strings.CutPrefix(id, "forget/"); ok && ForgetGoal(id) != "" {
		return "forget-agent/" + rest
	}
	if rest, ok := strings.CutPrefix(id, "forget-agent/"); ok && ForgetAgentGoal(id) != "" {
		return "forget/" + rest
	}
	return ""
}

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

// A journal.ActionUpdateFollow intent carries no params: the journal
// redacts params (journal.Redactor) and keeps identifiers as they are, so
// the name the owner gave the source and the digest of the root summary
// the page showed (update.RootSummary.Digest) ride in its ID (FollowID),
// as a forget's goal does. The updater follows that root and nothing else.
const (
	// FollowExecutor is the updater, which runs the switch.
	FollowExecutor = "update"
	// MaxFollowName bounds the owner-typed name, in characters.
	MaxFollowName = 40
	// MaxFollowDigits bounds the digits in that name, so it can carry a
	// year but never a code.
	MaxFollowDigits = 4
	// MaxFollowNonce bounds a follow intent's nonce, in hex characters.
	MaxFollowNonce = 64
)

// FollowID is the ID of a follow intent: nonce is unique per ask and is 1
// to MaxFollowNonce lower-case hex characters; the digest comes before the
// name, which may hold anything the gate's name check allows. An empty
// name switches back to the project. Any other nonce (one holding "/"
// would shift the parse, OSS-10w L3) gives an ID FollowOf refuses, so the
// gate denies it as malformed.
func FollowID(nonce, digest, name string) string {
	if !followNonce(nonce) {
		nonce = ""
	}
	return "follow/" + nonce + "/" + digest + "/" + name
}

func followNonce(s string) bool {
	if len(s) == 0 || len(s) > MaxFollowNonce {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// FollowOf is the digest and name a follow intent's ID names; ok is false
// if the ID is not FollowID's shape. The gate checks the values.
func FollowOf(id string) (digest, name string, ok bool) {
	rest, ok := strings.CutPrefix(id, "follow/")
	if !ok {
		return "", "", false
	}
	nonce, rest, ok := strings.Cut(rest, "/")
	if !ok || !followNonce(nonce) {
		return "", "", false
	}
	digest, name, ok = strings.Cut(rest, "/")
	if !ok || digest == "" {
		return "", "", false
	}
	return digest, name, true
}

// FollowIntent is the local page's request to follow the root whose
// summary has digest, under the owner's name for it ("" to switch back to
// the project's own root).
func FollowIntent(nonce, name, digest string) journal.Intent {
	return journal.Intent{ID: FollowID(nonce, digest, name), Origin: originLocal, Account: journal.BrokerAccount,
		Action: journal.ActionUpdateFollow, Executor: FollowExecutor}
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
//   - Resume: the ID of a paused grant to restore, and Pause, the ID of
//     the pause intent it ends (Grant.Pause), so an ask made before the
//     grant was paused again cannot end the later pause (W5a-resume).
//
// Every shape is a new or wider grant: high-tier code plus local
// confirmation (CH-3, CH-10).
type Spec struct {
	Account  string            `json:"account,omitempty"`
	Executor string            `json:"executor,omitempty"`
	Ops      map[string]string `json:"ops,omitempty"`
	Rule     *Rule             `json:"rule,omitempty"`
	Resume   string            `json:"resume,omitempty"`
	Pause    string            `json:"pause,omitempty"`
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
	// Pause is the intent that paused it, and PausedBy that intent's
	// origin; both are empty while it runs.
	Pause, PausedBy string
}

// fault is a refusal whose owner text may name the request's values; the
// guest's names only the field or cause, in fixed words (SR2-3o).
func fault(guest guesterr.Literal, format string, args ...any) refusal {
	return refusal{fmt.Sprintf(format, args...), guest}
}

// hint is the guest text for a malformed request: general, then the
// field or cause a refusal names.
func hint(general guesterr.Literal, err error) guesterr.Literal {
	var r refusal
	if errors.As(err, &r) && r.guest != "" {
		return general + ": " + r.guest
	}
	return general
}

// specTypes names, in fixed words, the type each spec field takes, by its
// JSON path (a map's or list's entries by the field's own).
var specTypes = map[string]guesterr.Literal{
	"":                "grant is an object",
	"account":         "account is a string",
	"executor":        "executor is a string",
	"ops":             "ops maps each operation to a verb, both strings",
	"resume":          "resume is a string",
	"pause":           "pause is a string",
	"rule":            "rule is an object",
	"rule.action":     "rule action is a string",
	"rule.params":     "rule params map names to strings",
	"rule.recipients": "rule recipients is a list of strings",
	"rule.amount_cap": "rule amount_cap is a whole number",
	"rule.per_record": "rule per_record is a whole number",
	"rule.per_day":    "rule per_day is a whole number",
	"rule.hold_days":  "rule hold_days is a whole number",
	"rule.reply":      "rule reply is true or false",
}

// specField is the spec field a JSON path falls under: a map key or list
// index below a field is the field's.
func specField(path string) string {
	parts := strings.SplitN(path, ".", 3)
	if parts[0] == "rule" && len(parts) > 1 {
		return "rule." + parts[1]
	}
	return parts[0]
}

// parseSpec reads a grant intent's spec strictly: unknown fields are an
// error, so nothing in the params is silently ignored.
func parseSpec(in journal.Intent) (Spec, error) {
	raw, ok := in.Params["grant"]
	if !ok || len(in.Params) != 1 {
		return Spec{}, refuse("a grant change carries exactly one param, grant")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return Spec{}, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	var s Spec
	if err := d.Decode(&s); err != nil {
		var te *json.UnmarshalTypeError
		if errors.As(err, &te) {
			if g, ok := specTypes[specField(te.Field)]; ok {
				return Spec{}, fault(g, "grant spec: %v", err)
			}
		}
		if strings.HasPrefix(err.Error(), "json: unknown field ") {
			return Spec{}, fault("the grant spec has a field it does not define", "grant spec: %v", err)
		}
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
		return refuse("a grant is exactly one of: an adapter grant, a pre-allowance, or a resume")
	}
	if s.Pause != "" && s.Resume == "" {
		return refuse("only a resume names a pause")
	}
	if s.Resume != "" {
		gr := g.grants[s.Resume]
		if gr == nil || !gr.Paused || s.Account != "" {
			return fault("resume names no paused grant, and no account", "no paused grant %s", clip(s.Resume))
		}
		// A resume recorded before W5a-resume names no pause; the gate
		// asks for one on every new resume (evaluateBroker).
		if s.Pause != "" && s.Pause != gr.Pause {
			return fault("the grant was paused again since the pause it names", "grant %s was paused again since", clip(s.Resume))
		}
		return nil
	}
	if s.Account == "" || s.Account == journal.BrokerAccount {
		return refuse("a grant names an external account")
	}
	if s.Rule == nil {
		declared := g.cfg.Declared[s.Executor]
		if s.Executor == ExecutorName || declared == nil {
			return fault("the executor is not a connected adapter", "executor %q is not a connected adapter", clip(s.Executor))
		}
		if len(s.Ops) == 0 {
			return refuse("an adapter grant chooses at least one operation")
		}
		for op, v := range s.Ops {
			dv, ok := declared[op]
			if !ok {
				return fault("an operation in ops is not one the adapter declares", "operation %q is not one the adapter declares", clip(op))
			}
			c, ok := verb.ClassOf(v)
			dc, _ := verb.ClassOf(dv)
			if !ok || c < dc {
				// ADP-2: the adapter's mapping is the floor; a grant can
				// only make an operation stricter.
				return fault("an operation's verb is weaker than the adapter's or not on the list", "operation %q: verb %q is weaker than the adapter's %q or not on the list", clip(op), clip(v), dv)
			}
		}
		for _, x := range g.grants {
			if x.Spec.Rule == nil && x.Spec.Account == s.Account {
				// One connection per account, so policy never depends on
				// which of two grants is found first (OP-5).
				return fault("another grant already connects this account; revoke it first", "%s already connects this account; revoke it first", x.ID)
			}
		}
		return nil
	}
	r := s.Rule
	ag := g.adapterLocked(s.Account)
	if ag == nil {
		return fault("no adapter grant connects the rule's account", "no adapter grant connects %s", clip(s.Account))
	}
	v, ok := ag.Spec.Ops[r.Action]
	if !ok {
		return fault("the rule's action is not an operation granted on its account", "operation %q is not declared for %s", clip(r.Action), clip(s.Account))
	}
	switch c, _ := verb.ClassOf(v); c {
	case verb.Reversible:
		return fault("the rule's action is reversible and needs no pre-allowance", "%s is %s, which needs no pre-allowance", clip(r.Action), v)
	case verb.Secret:
		return refuse("reveal-or-create-secret keeps per-action approval under any rule (CRED-6)")
	}
	if r.PerRecord < 1 || r.PerDay < 1 || r.AmountCap < 0 || r.HoldDays < 0 {
		return refuse("every rule has scope bounds: per_record and per_day of at least 1 (ADP-9)")
	}
	if r.Reply && (v != verb.Send || r.AmountCap != 0) {
		return refuse("a reply rule covers a send that moves no money (ADP-11)")
	}
	for k := range r.Params {
		if k == ParamRecord || k == ParamBody {
			return fault("rule params may not fix record or body", "param %q is filled per run, not fixed by the rule", k)
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
