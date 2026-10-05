package recovery

import (
	"encoding/json"
	"errors"
	"sort"
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
	// Declined lists standing grants the owner did not re-confirm. They
	// never run again; the broker also revokes them in the journal.
	Declined []string `json:"declined,omitempty"`
}

// stateValue pads the entry past the vault's minimum value length.
type stateValue struct {
	Format string `json:"format"`
	State
}

// LoadState reads the restore state. A malformed entry reads as
// restricted (fail closed).
func LoadState(v *vault.Vault) State {
	s, ok := v.Secret(StateName)
	if !ok {
		return State{}
	}
	var sv stateValue
	if err := json.Unmarshal([]byte(s.Reveal()), &sv); err != nil || sv.Format != "agentos-recovery-state-v1" {
		return State{Restricted: true, Source: "unknown"}
	}
	return sv.State
}

func saveState(v *vault.Vault, st State) error {
	b, err := json.Marshal(stateValue{"agentos-recovery-state-v1", st})
	if err != nil {
		return err
	}
	return v.Put(StateName, KindState, b)
}

// Permits says whether a grant or pre-allowance may run (REC-2): not while
// the box is restricted, and never one the owner declined to re-confirm.
// Grants made after the confirmation are permitted.
func (st State) Permits(grantID string) bool {
	if st.Restricted {
		return false
	}
	for _, d := range st.Declined {
		if d == grantID {
			return false
		}
	}
	return true
}

// BudgetRemaining is what a budget may still spend in its current period
// (REC-2: restore MUST NOT revive spent budgets). The restored record of
// spending is only as new as the backup or drive copy, so in a period that
// began before the restore the true spending is unknown, and the budget is
// treated as spent until the next period. Raising a budget stays a separate
// owner intent (OP-5) and is unaffected.
func (st State) BudgetRemaining(limit, spent int64, periodStart time.Time) int64 {
	if st.Restricted || (!st.RestoredAt.IsZero() && !periodStart.After(st.RestoredAt)) {
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

// Reconfirm ends restricted mode with the owner's answer for the whole
// list of standing grants, shown on the local page in fixed wording:
// those in keep run again, every other one stays off for good. It is a
// tier-4 action (CH-3): a code-generator code plus local confirmation, or
// the recovery key. The caller journals a revoke for each declined grant.
func Reconfirm(b *Box, standing []Standing, keep []string, auth Auth) (State, error) {
	if err := auth.check(b); err != nil {
		return State{}, err
	}
	st := LoadState(b.V)
	known := map[string]bool{}
	for _, s := range standing {
		known[s.ID] = true
	}
	kept := map[string]bool{}
	for _, id := range keep {
		if !known[id] {
			return State{}, errors.New("recovery: can only keep a grant from the standing list")
		}
		kept[id] = true
	}
	declined := map[string]bool{}
	for _, d := range st.Declined {
		declined[d] = true
	}
	for _, s := range standing {
		if !kept[s.ID] {
			declined[s.ID] = true
		}
	}
	next := State{RestoredAt: st.RestoredAt, Source: st.Source}
	for d := range declined {
		if !kept[d] {
			next.Declined = append(next.Declined, d)
		}
	}
	sort.Strings(next.Declined)
	if err := saveState(b.V, next); err != nil {
		return State{}, err
	}
	return next, nil
}
