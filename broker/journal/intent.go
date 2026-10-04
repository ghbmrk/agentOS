package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Intent is one requested effect, with every parameter that decides what the
// effect is (SPEC §9). Two submissions with the same ID must agree on all of
// these fields (OP-1).
type Intent struct {
	ID     string `json:"id"`
	GoalID string `json:"goal_id,omitempty"`
	// Origin names the authenticated source of the request. The broker
	// authenticates; the engine records.
	Origin string `json:"origin"`
	// Account is the external account (or "broker" for broker-state
	// changes) that the effect lands on. OP-4 fences dispatch per account.
	Account       string         `json:"account"`
	Action        string         `json:"action"`
	Params        map[string]any `json:"params,omitempty"`
	Recipients    []string       `json:"recipients,omitempty"`
	Visibility    string         `json:"visibility,omitempty"`
	GrantRef      string         `json:"grant_ref,omitempty"`
	Reservation   *Reservation   `json:"reservation,omitempty"`
	Preconditions []string       `json:"preconditions,omitempty"`
	Executor      string         `json:"executor"`
}

// Reservation is the budget held for an intent until it settles.
type Reservation struct {
	Amount int64  `json:"amount"`
	Unit   string `json:"unit"`
}

// BrokerAccount is the account of intents that change the broker's own
// state rather than an external account.
const BrokerAccount = "broker"

// Broker-state changes are intents too (OP-5): they use these actions, go
// through the same engine, and share the one journal and recovery rule.
const (
	ActionGrantChange       = "meta.grant"
	ActionBudgetChange      = "meta.budget"
	ActionTrustedHostChange = "meta.trusted_host"
	ActionReleaseActivate   = "meta.release"
	ActionSkillAdopt        = "meta.skill"
)

// Authority-narrowing broker-state changes. Pausing or revoking must always
// work (ADP-9), so on BrokerAccount these are exempt from STOP's hold and
// from restart fences. They only take authority away, so running one twice
// or during STOP cannot widen anything.
const (
	ActionGrantRevoke = "meta.grant.revoke" // also revokes a pre-allowance
	ActionGrantPause  = "meta.grant.pause"  // also pauses a pre-allowance or loop
	ActionBudgetLower = "meta.budget.lower"
)

// narrowing reports whether an intent only takes authority away.
func narrowing(in Intent) bool {
	if in.Account != BrokerAccount {
		return false
	}
	switch in.Action {
	case ActionGrantRevoke, ActionGrantPause, ActionBudgetLower:
		return true
	}
	return false
}

// State is an intent's position in the lifecycle.
type State string

const (
	Pending        State = "pending"
	Authorized     State = "authorized"
	Denied         State = "denied"
	InFlight       State = "in_flight"
	OutcomeUnknown State = "outcome_unknown"
	Succeeded      State = "succeeded"
	NotApplied     State = "not_applied"
)

// Result is what an executor, a reconciliation, or the owner reports about
// one attempt.
type Result string

const (
	ResultInFlight   Result = "in_flight"
	ResultSucceeded  Result = "succeeded"
	ResultNotApplied Result = "not_applied" // evidence that the effect did not happen
	ResultUnknown    Result = "unknown"
)

// Outcome is an executor's report on one attempt. Anything other than
// succeeded or not_applied is recorded as unknown.
type Outcome struct {
	Result   Result
	Evidence string
}

// Executor performs effects. Execute may be called at most once per
// (intent, attempt); AttemptKey gives a stable idempotency key for it.
// Reconcile asks the service what happened to an attempt, returning
// ResultUnknown when the service cannot tell.
type Executor interface {
	Execute(ctx context.Context, in Intent, attempt int) Outcome
	Reconcile(ctx context.Context, in Intent, attempt int) Outcome
}

// Canceller is implemented by executors whose service supports cancelling an
// effect in flight (OP-6). Acceptance is recorded, never treated as undo.
type Canceller interface {
	Cancel(ctx context.Context, in Intent, attempt int) (accepted bool, detail string)
}

// AttemptKey is the idempotency key for one attempt of an intent.
func AttemptKey(id string, attempt int) string { return fmt.Sprintf("%s#%d", id, attempt) }

// Phase says when a policy check runs.
type Phase string

const (
	PhaseAuthorize Phase = "authorize"
	PhaseDispatch  Phase = "dispatch" // the recheck immediately before dispatch (OP-3)
)

// Policy decides authority, recipients, preconditions, and reservations.
//
// Check runs without the engine lock, so a slow check never delays STOP. The
// engine commits the decision only if no journal record was written while
// Check ran; otherwise it checks again. Authority changes are themselves
// intents (OP-5), so a grant revoked during a check forces a fresh check
// before dispatch (OP-3). Policy state that can change outside the engine
// (for example an approval code's expiry) must be read inside Check.
type Policy interface {
	Check(ctx context.Context, phase Phase, in Intent) error
}

// Verdict is the owner's (or a grader's) judgment of goal quality, recorded
// apart from permission and execution (OP-7).
type Verdict string

const (
	VerdictGood  Verdict = "good"
	VerdictWrong Verdict = "wrong"
)

// Permission records the authorization decision and where it was made.
type Permission struct {
	Decision string `json:"decision,omitempty"` // "allowed" or "denied"
	Phase    Phase  `json:"phase,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Attempt records one dispatch and what is known about it.
type Attempt struct {
	N        int      `json:"n"`
	Result   Result   `json:"result"`
	Source   string   `json:"source,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
	Cancels  []Cancel `json:"cancels,omitempty"`
}

// Cancel records a cancellation request made by STOP.
type Cancel struct {
	Accepted bool   `json:"accepted"`
	Detail   string `json:"detail,omitempty"`
}

// Quality records a judgment of whether the effect served the goal.
type Quality struct {
	Verdict Verdict `json:"verdict,omitempty"`
	Source  string  `json:"source,omitempty"`
	Note    string  `json:"note,omitempty"`
}

// Status is a snapshot of one intent. Permission, execution (Attempts), and
// Quality are separate fields that never imply one another (OP-7).
type Status struct {
	Intent     Intent
	State      State
	Permission Permission
	Attempts   []Attempt
	Quality    Quality
}

var (
	ErrInvalid      = errors.New("journal: invalid intent")
	ErrConflict     = errors.New("journal: same intent ID with different parameters")
	ErrNotFound     = errors.New("journal: no such intent")
	ErrState        = errors.New("journal: not allowed in the intent's current state")
	ErrStopped      = errors.New("journal: stopped; dispatch is blocked")
	ErrUnreconciled = errors.New("journal: account has intents left unresolved by a restart")
	ErrRecheck      = errors.New("journal: recheck before dispatch failed")
	ErrNoExecutor   = errors.New("journal: executor not registered")
	ErrCorrupt      = errors.New("journal: corrupt journal")
	ErrBroken       = errors.New("journal: a journal write failed; reopen to recover")
	ErrBusy         = errors.New("journal: state kept changing during the policy check; retry")
	ErrLocked       = errors.New("journal: journal file is open in another process")
)

// Redactor rewrites free text before it is journaled, removing secrets
// (CRED-1, CRED-7). The broker supplies one that strips vault values and the
// CH-19 secret patterns. It is applied to intent params, recipients and
// preconditions, and to evidence, reasons, cancel details and quality notes.
// Identifiers (ID, account, action, executor, grant ref) are not redacted.
type Redactor func(string) string

// Size limits. An intent larger than MaxIntentBytes is rejected; free text
// longer than MaxTextBytes is cut and tagged with a hash of the whole.
const (
	MaxIntentBytes = 64 << 10
	MaxTextBytes   = 4 << 10
)

// normalize deep-copies an intent through its JSON form, so the in-memory
// copy is exactly what replay would produce.
func normalize(in Intent) (Intent, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return Intent{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	var out Intent
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&out); err != nil {
		return Intent{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return out, nil
}

// effectFingerprint hashes only what decides the external effect: where,
// what, to whom. Two intents with equal effect fingerprints under different
// IDs may be the same effect submitted twice (OP-2).
func effectFingerprint(in Intent) string {
	b, _ := json.Marshal(struct {
		Account    string
		Action     string
		Params     map[string]any
		Recipients []string
		Visibility string
		Executor   string
	}{in.Account, in.Action, in.Params, in.Recipients, in.Visibility, in.Executor})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// fingerprint is a hash over every field of the intent. encoding/json sorts
// map keys, so equal parameters give equal fingerprints.
func fingerprint(in Intent) string {
	b, _ := json.Marshal(in)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
