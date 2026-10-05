package recovery

import (
	"errors"
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
	nb, _, err := x.restore(bk, x.rk, restoredAt)
	must(t, err)
	st := LoadState(nb.V)
	for _, g := range []string{"G1", "G2", "G9"} {
		if st.Permits(g) {
			t.Fatalf("%s runs before the owner re-confirms", g)
		}
	}
	period := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) // began before the restore
	if got := st.BudgetRemaining(10000, 1500, period); got != 0 {
		t.Fatalf("restricted budget: %d", got)
	}

	// Re-confirmation is tier-4.
	for _, a := range []Auth{{}, {Code: true}, {Local: true}, {Recovery: mustKey(t)}} {
		if _, err := Reconfirm(nb, standing, []string{"G2"}, a); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("auth %+v: %v", a, err)
		}
	}
	if _, err := Reconfirm(nb, standing, []string{"G7"}, Auth{Code: true, Local: true}); err == nil {
		t.Fatal("kept a grant that was not standing")
	}
	// The owner keeps G2, not G1 (the one revoked after the backup).
	st, err = Reconfirm(nb, standing, []string{"G2"}, Auth{Code: true, Local: true})
	must(t, err)
	if st.Restricted || st.Permits("G1") || !st.Permits("G2") || !st.Permits("G3") {
		t.Fatalf("after re-confirmation: %+v", st)
	}
	// The answer is durable: it is in the vault.
	st2 := LoadState(openAt(t, nb.VaultPath[:len(nb.VaultPath)-len(lay.Vault)], x.rk).V)
	if st2.Permits("G1") || !st2.Permits("G2") {
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
	// The recovery key is the alternative authority (CH-3).
	_, err = Reconfirm(nb, nil, nil, Auth{Recovery: x.rk})
	must(t, err)
}

func TestRestrictedStateFailsClosedWhenMalformed(t *testing.T) {
	x := newBox(t)
	if st := LoadState(x.b.V); st.Restricted {
		t.Fatal("a box that was never restored is restricted")
	}
	must(t, x.b.V.Put(StateName, KindState, []byte(`{"restricted":false,"format":"other"}`)))
	if st := LoadState(x.b.V); !st.Restricted || st.Permits("G1") {
		t.Fatal("malformed state is not restricted")
	}
	must(t, x.b.V.Put(StateName, KindState, []byte("not json at all, longer")))
	if st := LoadState(x.b.V); !st.Restricted {
		t.Fatal("unparsable state is not restricted")
	}
	// Nothing outside the vault can clear it: the entry is sealed with
	// the vault, and a modified vault does not open.
	must(t, saveState(x.b.V, State{Restricted: true}))
	if _, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, Factor(x.rk)); err != nil {
		t.Fatal(err)
	}
}
