package recovery

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/vault"
)

// State is what the broker must know about a restore (REC-2). It is a
// vault entry, so it is read only after unlock and cannot be changed
// without the data key. A vault with no entry is a box that was never
// restored. Rolling the whole vault back to an older copy is not
// detectable from the drive alone; that is the V6 rollback counter
// (P2-4b, egress ASSUMPTIONS V6).
type State struct {
	// Restricted: the box was restored and the owner has not yet
	// re-confirmed its standing grants. No grant or pre-allowance runs.
	Restricted bool `json:"restricted"`
	// RestoredAt is when the last restore happened. A budget period that
	// began before it counts as fully spent (BudgetRemaining).
	RestoredAt time.Time `json:"restored_at,omitempty"`
	// Source is "backup" or "drive".
	Source string `json:"source,omitempty"`
	// Unverified: the broker state came from the old drive, which nothing
	// authenticates, so its owner number and grants are the owner's only
	// once re-confirmed. Cleared by Reconfirm.
	Unverified bool `json:"unverified,omitempty"`
	// ConfirmedAt is when the owner re-confirmed. Only a kept grant, or
	// one created after this, runs.
	ConfirmedAt time.Time `json:"confirmed_at,omitempty"`
	// Kept lists the standing grants the owner re-confirmed.
	Kept []string `json:"kept,omitempty"`
	// Declined lists standing grants the owner did not re-confirm. They
	// never run again; the broker also revokes them in the journal.
	Declined []string `json:"declined,omitempty"`
	// FreshBudgets: the owner chose to start the restore period's
	// budgets fresh instead of treating them as spent.
	FreshBudgets bool `json:"fresh_budgets,omitempty"`
	// Pending says why the restore's forget log was not checked (Pending*
	// in forgetlog.go), recorded beside the state dir's marker, which
	// keeps agentosd from starting until the owner confirms it
	// (W3-forget-b1-4). Re-confirming grants does not clear it.
	Pending string `json:"pending,omitempty"`
}

const stateFormat = "agentos-recovery-state-v2"

// stateValue pads the entry past the vault's minimum value length.
type stateValue struct {
	Format string `json:"format"`
	State
}

// failClosed is the state of a box whose restore record is unreadable.
var failClosed = State{Restricted: true, Unverified: true, Source: "unknown"}

// LoadState reads the restore state. A malformed entry, or one of another
// kind, reads as restricted (fail closed).
func LoadState(v *vault.Vault) State {
	kind, ok := entryKind(v, StateName)
	if !ok {
		return State{}
	}
	s, ok := v.Secret(StateName)
	if !ok || kind != KindState {
		return failClosed
	}
	var sv stateValue
	d := json.NewDecoder(strings.NewReader(s.Reveal()))
	d.DisallowUnknownFields()
	if err := d.Decode(&sv); err != nil || sv.Format != stateFormat {
		return failClosed
	}
	return sv.State
}

// entryKind is the kind of the vault entry name, if it exists.
func entryKind(v *vault.Vault, name string) (string, bool) {
	for _, e := range v.List() {
		if e.Name == name {
			return e.Kind, true
		}
	}
	return "", false
}

func saveState(v *vault.Vault, st State) error {
	b, err := json.Marshal(stateValue{stateFormat, st})
	if err != nil {
		return err
	}
	return v.Put(StateName, KindState, b)
}

// Permits says whether a grant or pre-allowance may run (REC-2). Nothing
// runs while the box is restricted, and a declined grant never runs. On a
// box that was ever restored, a grant runs only if the owner kept it or it
// was created after the re-confirmation; the caller passes the time the
// live broker recorded the grant. A grant the restored record carried is
// on the standing list, so it is either kept or declined whatever time it
// claims.
func (st State) Permits(grantID string, created time.Time) bool {
	if st.Restricted {
		return false
	}
	if contains(st.Declined, grantID) {
		return false
	}
	if st.RestoredAt.IsZero() {
		return true
	}
	return contains(st.Kept, grantID) || created.After(st.ConfirmedAt)
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// BudgetRemaining is what a budget may still spend in its current period
// (REC-2: restore MUST NOT revive spent budgets). The restored record of
// spending is only as new as the backup or drive copy, so in a period that
// began before the restore the true spending is unknown, and the budget is
// treated as spent until the next period, unless the owner chose to start
// it fresh when re-confirming. Raising a budget stays a separate owner
// intent (OP-5) and is unaffected.
func (st State) BudgetRemaining(limit, spent int64, periodStart time.Time) int64 {
	if st.Restricted {
		return 0
	}
	if !st.FreshBudgets && !st.RestoredAt.IsZero() && !periodStart.After(st.RestoredAt) {
		return 0
	}
	if spent >= limit {
		return 0
	}
	return limit - spent
}

// Standing is a grant that existed when the box was restored, in the fixed
// wording the owner confirms (grants.Describe).
type Standing struct {
	ID   string
	Text string
}

// Answer is the owner's one answer on the local page for the whole
// standing list, which the caller lists in full from the restored record.
type Answer struct {
	Standing []Standing
	// Keep lists the grants that run again; KeepAll keeps every one.
	Keep    []string
	KeepAll bool
	// DeclineAll is the explicit answer for keeping none: an empty Keep
	// alone is refused while grants stand.
	DeclineAll bool
	// FreshBudgets starts the restore period's budgets fresh.
	FreshBudgets bool
}

// ErrEmptyAnswer is an answer that keeps nothing without saying so.
var ErrEmptyAnswer = errors.New("recovery: choose the grants to keep, Keep all, or Turn all off")

// Reconfirm ends restricted mode with the owner's answer: kept grants run
// again, every other standing one stays off for good. It is a tier-4
// action (CH-3): a code-generator code plus local confirmation, or the
// recovery key. The caller journals a revoke for each declined grant.
func Reconfirm(b *Box, ans Answer, auth Auth, now time.Time) (State, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := auth.check(b); err != nil {
		return State{}, err
	}
	known := map[string]bool{}
	for _, s := range ans.Standing {
		known[s.ID] = true
	}
	kept := map[string]bool{}
	if ans.KeepAll {
		for id := range known {
			kept[id] = true
		}
	}
	for _, id := range ans.Keep {
		if !known[id] {
			return State{}, errors.New("recovery: can only keep a grant from the standing list")
		}
		kept[id] = true
	}
	if len(known) > 0 && len(kept) == 0 && !ans.DeclineAll {
		return State{}, ErrEmptyAnswer
	}
	if ans.DeclineAll && len(kept) > 0 {
		return State{}, errors.New("recovery: an answer cannot keep grants and turn all off")
	}
	st := LoadState(b.V)
	declined := map[string]bool{}
	for _, d := range st.Declined {
		declined[d] = true
	}
	for _, s := range ans.Standing {
		if !kept[s.ID] {
			declined[s.ID] = true
		}
	}
	next := State{RestoredAt: st.RestoredAt, Source: st.Source, ConfirmedAt: now.UTC(), FreshBudgets: ans.FreshBudgets, Pending: st.Pending}
	if next.RestoredAt.IsZero() {
		// An unreadable state entry: the restore time is unknown, so the
		// current period counts as the restore's.
		next.RestoredAt = now.UTC()
	}
	// A decline is for good: a later answer cannot keep it.
	for d := range declined {
		next.Declined = append(next.Declined, d)
	}
	for k := range kept {
		if !declined[k] {
			next.Kept = append(next.Kept, k)
		}
	}
	sort.Strings(next.Declined)
	sort.Strings(next.Kept)
	if err := saveState(b.V, next); err != nil {
		return State{}, err
	}
	return next, nil
}
