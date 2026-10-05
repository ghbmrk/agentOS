package recovery

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: REC-2
// Acceptance: A8 (revoked grants are not revived)

func TestRestoreDoesNotReviveRevokedGrantsOrSpentBudgets(t *testing.T) {
	x := newBox(t)
	bk := x.backup() // G1 and G2 stand at backup time
	// After the backup the owner revoked G1 and spent most of a budget;
	// then the drive was lost, so the restore cannot know either.
	standing := []Standing{{"G1", "Connect account mail ..."}, {"G2", "Let send on calendar run ..."}}
	restoredAt := t0.Add(72 * time.Hour)
	confirmAt := restoredAt.Add(time.Hour)
	nb, _, err := x.restore(bk, x.rk, restoredAt)
	must(t, err)
	st := LoadState(nb.V)
	for _, g := range []string{"G1", "G2", "G9"} {
		if st.Permits(g, confirmAt.Add(time.Hour)) {
			t.Fatalf("%s runs before the owner re-confirms", g)
		}
	}
	period := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) // began before the restore
	if got := st.BudgetRemaining(10000, 1500, period); got != 0 {
		t.Fatalf("restricted budget: %d", got)
	}

	// Re-confirmation is tier-4.
	ans := Answer{Standing: standing, Keep: []string{"G2"}}
	for _, a := range []Auth{{}, {Code: true}, {Local: true}, {Recovery: mustKey(t)}} {
		if _, err := Reconfirm(nb, ans, a, confirmAt); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("auth %+v: %v", a, err)
		}
	}
	if _, err := Reconfirm(nb, Answer{Standing: standing, Keep: []string{"G7"}}, Auth{Code: true, Local: true}, confirmAt); err == nil {
		t.Fatal("kept a grant that was not standing")
	}
	// Keeping nothing must be said, not implied by an empty list.
	if _, err := Reconfirm(nb, Answer{Standing: standing}, Auth{Code: true, Local: true}, confirmAt); !errors.Is(err, ErrEmptyAnswer) {
		t.Fatalf("empty answer: %v", err)
	}
	// The owner keeps G2, not G1 (the one revoked after the backup).
	st, err = Reconfirm(nb, ans, Auth{Code: true, Local: true}, confirmAt)
	must(t, err)
	if st.Restricted || st.Permits("G1", t0) || !st.Permits("G2", t0) {
		t.Fatalf("after re-confirmation: %+v", st)
	}
	// A grant from the restored record that the caller left off the
	// standing list does not run; one made after the answer does.
	if st.Permits("G3", restoredAt) || st.Permits("G3", confirmAt) || !st.Permits("G4", confirmAt.Add(time.Minute)) {
		t.Fatalf("unlisted grants: %+v", st)
	}
	// A declined grant stays off whatever creation time it claims.
	if st.Permits("G1", confirmAt.Add(24*time.Hour)) {
		t.Fatal("declined grant runs with a later timestamp")
	}
	// The answer is durable: it is in the vault.
	st2 := LoadState(openAt(t, nb.VaultPath[:len(nb.VaultPath)-len(lay.Vault)], x.rk).V)
	if st2.Permits("G1", t0) || !st2.Permits("G2", t0) || st2.Permits("G3", t0) {
		t.Fatalf("reloaded: %+v", st2)
	}
	// Spending in the period the restore fell in stays closed; the next
	// period starts fresh. A raise is a separate owner intent.
	if got := st2.BudgetRemaining(10000, 1500, period); got != 0 {
		t.Fatalf("spent budget revived: %d", got)
	}
	if got := st2.BudgetRemaining(10000, 1500, restoredAt.Add(24*time.Hour)); got != 8500 {
		t.Fatalf("next period: %d", got)
	}
	// The recovery key is the alternative authority (CH-3); "Keep all"
	// and "start budgets fresh" are part of the same answer.
	st, err = Reconfirm(nb, Answer{Standing: standing, KeepAll: true, FreshBudgets: true}, Auth{Recovery: x.rk}, confirmAt)
	must(t, err)
	if st.Permits("G1", t0) || !st.Permits("G2", t0) {
		t.Fatalf("keep all revived an earlier decline: %+v", st)
	}
	if got := st.BudgetRemaining(10000, 1500, period); got != 8500 {
		t.Fatalf("fresh budgets: %d", got)
	}
	st, err = Reconfirm(nb, Answer{Standing: []Standing{{"G5", "..."}}, DeclineAll: true}, Auth{Recovery: x.rk}, confirmAt)
	must(t, err)
	if st.Permits("G5", t0) {
		t.Fatal("decline all kept a grant")
	}
}

// Two answers at once cannot interleave and revive a declined grant.
func TestReconfirmIsSerialized(t *testing.T) {
	x := newBox(t)
	nb, _, err := x.restore(x.backup(), x.rk, t0)
	must(t, err)
	standing := []Standing{{"G1", "a"}, {"G2", "b"}}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		keep := []string{"G1"}
		if i%2 == 1 {
			keep = []string{"G2"}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			Reconfirm(nb, Answer{Standing: standing, Keep: keep}, Auth{Code: true, Local: true}, t0)
		}()
	}
	wg.Wait()
	// Each answer declines one of the two, and declines are for good, so
	// neither runs; an interleaved write would drop one decline.
	st := LoadState(nb.V)
	if st.Permits("G1", t0) || st.Permits("G2", t0) {
		t.Fatalf("a declined grant runs: %+v", st)
	}
}

func TestRestrictedStateFailsClosedWhenMalformed(t *testing.T) {
	x := newBox(t)
	if st := LoadState(x.b.V); st.Restricted {
		t.Fatal("a box that was never restored is restricted")
	}
	must(t, x.b.V.Put(StateName, KindState, []byte(`{"restricted":false,"format":"other"}`)))
	if st := LoadState(x.b.V); !st.Restricted || st.Permits("G1", t0) {
		t.Fatal("malformed state is not restricted")
	}
	must(t, x.b.V.Put(StateName, KindState, []byte("not json at all, longer")))
	if st := LoadState(x.b.V); !st.Restricted {
		t.Fatal("unparsable state is not restricted")
	}
	// A well-formed value under another kind (as a credential write
	// would store it) is not the restore state.
	must(t, x.b.V.Put(StateName, vault.KindAPIKey, []byte(`{"format":"`+stateFormat+`","restricted":false}`)))
	if st := LoadState(x.b.V); !st.Restricted {
		t.Fatal("state of the wrong kind lifts restricted mode")
	}
	// Nothing outside the vault can clear it: the entry is sealed with
	// the vault, and a modified vault does not open.
	must(t, saveState(x.b.V, State{Restricted: true}))
	if _, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, Factor(x.rk)); err != nil {
		t.Fatal(err)
	}
}
