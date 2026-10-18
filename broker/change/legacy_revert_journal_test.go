package change

import (
	"bytes"
	"testing"
)

// REQ: OP-11, SM-AD-2, LRJ-1, LRJ-2, LRJ-3

// CHG-legacy-revert-journal: a forget or settings revert that a state
// saved before the journal held the lifecycle kept in a body's legacy
// lifecycle is journaled once and leaves the body, like the top-level
// revert CHG-forget-revert-journal migrates.

// withLegacy is body with a legacy lifecycle holding lc.
func withLegacy(body []byte, lc string) []byte {
	return bytes.Replace(body, []byte(`{`), []byte(`{"legacy":`+lc+`,`), 1)
}

// LRJ-1, LRJ-2
func TestLegacyForgetRevertIsJournaled(t *testing.T) {
	e, rep := forgetEnv(t)
	plain := e.body(rep.ID)
	e.asEarlierBuild()
	e.putBody(rep.ID, withLegacy(plain, `{"confirmed":true,"reverted":"forgotten"}`))
	e.reopen()
	if got := e.reverted(rep.ID); got != WhyForgotten {
		t.Fatalf("legacy revert lost: %q", got)
	}
	if got := e.revertsJournaled(rep.ID); len(got) != 1 || got[0] != WhyForgotten {
		t.Fatalf("revert intents: %q", got)
	}
	e.noRevertOnDisk(rep.ID)
	// The rest of the legacy lifecycle moved to the state (ABT-2).
	if l := e.savedState().Legacy[rep.ID]; l == nil || !l.Confirmed || l.Reverted != "" {
		t.Fatalf("the rest of the legacy lifecycle went: %+v", l)
	}

	// LRJ-2: the body restored without the field, or with it, still
	// replays as reverted, and nothing is journaled twice.
	for _, b := range [][]byte{withLegacy(plain, `{"confirmed":true}`), plain,
		withLegacy(plain, `{"confirmed":true,"reverted":"forgotten"}`)} {
		e.putBody(rep.ID, b)
		e.reopen()
		if got := e.reverted(rep.ID); got != WhyForgotten {
			t.Fatalf("restored body brought the adoption back: %q (%s)", got, b)
		}
		if got := e.revertsJournaled(rep.ID); len(got) != 1 {
			t.Fatalf("revert intents: %q", got)
		}
	}
	e.noRevertOnDisk(rep.ID)
}

// LRJ-1, LRJ-2
func TestLegacySettingsRevertIsJournaled(t *testing.T) {
	e, rep, _ := settingsEnv(t)
	plain := e.body(rep.ID)
	e.asEarlierBuild()
	e.putBody(rep.ID, withLegacy(plain, `{"reverted":"settings"}`))
	e.reopen()
	if got := e.revertsJournaled(rep.ID); len(got) != 1 || got[0] != WhySettings {
		t.Fatalf("revert intents: %q", got)
	}
	e.noRevertOnDisk(rep.ID)
	e.putBody(rep.ID, plain)
	e.reopen()
	if got := e.reverted(rep.ID); got != WhySettings {
		t.Fatalf("restored body brought the adoption back: %q", got)
	}
}

// LRJ-3: the debt is saved before the body loses its legacy revert.
func TestLegacyRevertMigrationSurvivesAFailedSave(t *testing.T) {
	e, rep := forgetEnv(t)
	e.asEarlierBuild()
	e.putBody(rep.ID, withLegacy(e.body(rep.ID), `{"reverted":"forgotten"}`))
	e.p.cfg.Store = &flakyStore{MemStore: e.store, failSave: true}
	e.reopen()
	if !bytes.Contains(e.body(rep.ID), []byte(`"reverted":"forgotten"`)) {
		t.Fatal("the body lost its legacy revert before the debt was saved")
	}
	e.p.cfg.Store = e.store
	e.reopen()
	if got := e.revertsJournaled(rep.ID); len(got) != 1 || got[0] != WhyForgotten {
		t.Fatalf("revert intents: %q", got)
	}
	e.noRevertOnDisk(rep.ID)
}

// LRJ-3: a legacy revert the journal does not own (any why but forgotten
// or settings) stays the legacy lifecycle's, now kept in the state (ABT-2).
func TestLegacyOtherRevertStaysInTheBody(t *testing.T) {
	e, rep := forgetEnv(t)
	e.asEarlierBuild()
	e.putBody(rep.ID, withLegacy(e.body(rep.ID), `{"reverted":"`+WhyDropped+`"}`))
	e.reopen()
	if got := e.reverted(rep.ID); got != WhyDropped {
		t.Fatalf("legacy revert: %q", got)
	}
	if got := e.revertsJournaled(rep.ID); len(got) != 0 {
		t.Fatalf("revert intents: %q", got)
	}
	// The state keeps the revert, so a later start still sees it.
	if l := e.savedState().Legacy[rep.ID]; l == nil || l.Reverted != WhyDropped {
		t.Fatalf("the state lost the revert: %+v", l)
	}
	e.reopen()
	if got := e.reverted(rep.ID); got != WhyDropped {
		t.Fatalf("after a second start: %q", got)
	}
}
