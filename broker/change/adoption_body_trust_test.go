package change

import (
	"bytes"
	"encoding/json"
	"testing"
)

// REQ: CAP-3, OP-11, SM-AD-2, ABT-1, ABT-2, ABT-3 (and C23)

// CHG-adoption-body-trust: Content is writable by whoever cannot write
// the state, so replay takes no lifecycle from an adoption body once the
// state says the bodies were migrated.

// asEarlierBuild turns the saved state back into one an earlier build
// saved: no body-trust mark and no legacy lifecycles in it.
func (e *env) asEarlierBuild() {
	e.t.Helper()
	raw, err := e.store.Load()
	if err != nil {
		e.t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		e.t.Fatal(err)
	}
	delete(m, "legacy_in_state")
	delete(m, "legacy")
	b, _ := json.Marshal(m)
	if err := e.store.Save(b); err != nil {
		e.t.Fatal(err)
	}
}

// savedState is the state as the store holds it.
func (e *env) savedState() state {
	e.t.Helper()
	raw, err := e.store.Load()
	if err != nil {
		e.t.Fatal(err)
	}
	var st state
	if err := json.Unmarshal(raw, &st); err != nil {
		e.t.Fatal(err)
	}
	return st
}

// ABT-1
func TestForgedBodyLifecycleIsIgnored(t *testing.T) {
	for _, forge := range []func([]byte) []byte{
		func(b []byte) []byte { return withLegacy(b, `{"reverted":"forgotten"}`) },
		func(b []byte) []byte { return withLegacy(b, `{"reverted":"settings"}`) },
		func(b []byte) []byte { return withLegacy(b, `{"reverted":"`+WhyDropped+`"}`) },
		func(b []byte) []byte { return withLegacy(b, `{"staged":true,"confirmed":true}`) },
		func(b []byte) []byte { return bytes.Replace(b, []byte(`{`), []byte(`{"reverted":"forgotten",`), 1) },
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`{`), []byte(`{"reverted":"`+WhyDropped+`",`), 1)
		},
	} {
		e, rep := forgetEnv(t)
		plain := e.body(rep.ID)
		forged := forge(plain)
		e.putBody(rep.ID, forged)
		e.reopen()
		if got := e.reverted(rep.ID); got != "" {
			t.Fatalf("%s: a forged body reverted the adoption: %q", forged, got)
		}
		if a := e.adoption(rep.ID); a.Staged || a.Confirmed {
			t.Fatalf("%s: a forged body changed the lifecycle: %+v", forged, a)
		}
		if got := e.revertsJournaled(rep.ID); len(got) != 0 {
			t.Fatalf("%s: revert intents: %q", forged, got)
		}
		if !bytes.Equal(e.body(rep.ID), plain) {
			t.Fatalf("%s: the forged fields stayed in the body: %s", forged, e.body(rep.ID))
		}
		// C23: the forget still reaches the adoption, and its bytes go.
		if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
			t.Fatal(err)
		}
		if got := e.revertsJournaled(rep.ID); len(got) != 1 || got[0] != WhyForgotten {
			t.Fatalf("%s: revert intents after the forget: %q", forged, got)
		}
		if _, ok := e.p.Files("skills")["skills/note"]; ok {
			t.Fatalf("%s: the goal's bytes outlived its forget", forged)
		}
		if len(e.savedState().Legacy) != 0 {
			t.Fatalf("%s: a forged lifecycle reached the state", forged)
		}
	}
}

// ABT-2: an earlier build's body is trusted once; its legacy lifecycle
// then lives in the state, and the body no longer speaks for it.
func TestEarlierBuildLegacyMovesToTheState(t *testing.T) {
	e, rep := forgetEnv(t)
	plain := e.body(rep.ID)
	e.asEarlierBuild()
	e.putBody(rep.ID, withLegacy(plain, `{"reverted":"`+WhyDropped+`"}`))
	e.reopen()
	if got := e.reverted(rep.ID); got != WhyDropped {
		t.Fatalf("earlier build's legacy revert lost: %q", got)
	}
	st := e.savedState()
	if !st.LegacyInState || st.Legacy[rep.ID] == nil || st.Legacy[rep.ID].Reverted != WhyDropped {
		t.Fatalf("legacy lifecycle not in the state: %v %+v", st.LegacyInState, st.Legacy)
	}
	if !bytes.Equal(e.body(rep.ID), plain) {
		t.Fatalf("the body kept its lifecycle: %s", e.body(rep.ID))
	}
	// The body, restored or rewritten, no longer changes it.
	for _, b := range [][]byte{plain, withLegacy(plain, `{}`), withLegacy(plain, `{"reverted":"forgotten"}`)} {
		e.putBody(rep.ID, b)
		e.reopen()
		if got := e.reverted(rep.ID); got != WhyDropped {
			t.Fatalf("%s: legacy revert: %q", b, got)
		}
		if got := e.revertsJournaled(rep.ID); len(got) != 0 {
			t.Fatalf("%s: revert intents: %q", b, got)
		}
	}
}

// ABT-2: a pre-journal state's migration keeps the lifecycle in the state.
func TestPreJournalLegacyIsInTheState(t *testing.T) {
	e, rep := forgetEnv(t)
	plain := e.body(rep.ID)
	a := e.adoption(rep.ID)
	a.Reverted = WhyDropped
	raw, err := e.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "legacy_in_state")
	delete(m, "legacy")
	m["adoptions"], _ = json.Marshal([]*Adoption{&a})
	b, _ := json.Marshal(m)
	if err := e.store.Save(b); err != nil {
		t.Fatal(err)
	}
	e.reopen()
	if got := e.reverted(rep.ID); got != WhyDropped {
		t.Fatalf("pre-journal revert lost: %q", got)
	}
	if st := e.savedState(); !st.LegacyInState || st.Legacy[rep.ID] == nil || st.Legacy[rep.ID].Reverted != WhyDropped {
		t.Fatalf("legacy lifecycle not in the state: %+v", st.Legacy)
	}
	if !bytes.Equal(e.body(rep.ID), plain) {
		t.Fatalf("the body holds a lifecycle: %s", e.body(rep.ID))
	}
	e.putBody(rep.ID, withLegacy(plain, `{}`))
	e.reopen()
	if got := e.reverted(rep.ID); got != WhyDropped {
		t.Fatalf("a rewritten body changed the legacy lifecycle: %q", got)
	}
}

// ABT-3: the mark and the legacy lifecycle are saved before any body
// loses its lifecycle; a failed save leaves both as they were.
func TestBodyTrustMarkSavedBeforeBodiesStrip(t *testing.T) {
	e, rep := forgetEnv(t)
	e.asEarlierBuild()
	old := withLegacy(e.body(rep.ID), `{"reverted":"`+WhyDropped+`"}`)
	e.putBody(rep.ID, old)
	e.p.cfg.Store = &flakyStore{MemStore: e.store, failSave: true}
	e.reopen()
	if !bytes.Equal(e.body(rep.ID), old) {
		t.Fatal("the body lost its lifecycle before the state held it")
	}
	if e.savedState().LegacyInState {
		t.Fatal("the mark was saved by a failed save")
	}
	e.p.cfg.Store = e.store
	e.reopen()
	if got := e.reverted(rep.ID); got != WhyDropped {
		t.Fatalf("legacy revert lost: %q", got)
	}
	if st := e.savedState(); !st.LegacyInState || st.Legacy[rep.ID] == nil {
		t.Fatalf("legacy lifecycle not in the state: %+v", st.Legacy)
	}
}
