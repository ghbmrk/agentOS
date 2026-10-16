package change

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/route"
)

// REQ: OP-11, SM-AD-2, FRJ-1, FRJ-2, FRJ-3, FRJ-4

// CHG-forget-revert-journal: the forget and settings reverts are journal
// intents like every other transition, so replay reads them from the
// journal and never from the adoption's body.

// revertsJournaled lists the whys of id's succeeded revert intents.
func (e *env) revertsJournaled(id string) []string {
	var out []string
	for _, st := range e.eng.List() {
		parts := parseID(st.Intent.ID)
		if st.State == journal.Succeeded && len(parts) == 5 && parts[1] == id && parts[2] == "revert" {
			out = append(out, parts[4])
		}
	}
	return out
}

func (e *env) reverted(id string) string {
	e.t.Helper()
	for _, a := range e.p.Adoptions() {
		if a.ID == id {
			return a.Reverted
		}
	}
	e.t.Fatalf("no adoption %s", id)
	return ""
}

func (e *env) body(id string) []byte {
	e.t.Helper()
	b, err := e.p.content.Get(adoptionKey(id))
	if err != nil || b == nil {
		e.t.Fatalf("body of %s: %v", id, err)
	}
	return b
}

func (e *env) putBody(id string, b []byte) {
	e.t.Helper()
	if err := e.p.content.Put(adoptionKey(id), b); err != nil {
		e.t.Fatal(err)
	}
}

// noRevertOnDisk: neither the state nor the body holds a revert.
func (e *env) noRevertOnDisk(id string) {
	e.t.Helper()
	raw, err := e.store.Load()
	if err != nil {
		e.t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"reverted"`)) {
		e.t.Fatal("the saved state holds a revert")
	}
	if bytes.Contains(e.body(id), []byte(`"reverted"`)) {
		e.t.Fatal("the body holds a revert")
	}
}

func forgetEnv(t *testing.T) (*env, Report) {
	t.Helper()
	e := newEnv(t, func(c *Config) { c.Targets = map[string]Target{"skills": &fakeTarget{ns: "skills"}} })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	rep := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": []byte("g1 note")}})
	if rep.State != StateAdopted {
		t.Fatalf("setup: %+v", rep)
	}
	return e, rep
}

func settingsEnv(t *testing.T) (*env, Report, Tree) {
	t.Helper()
	cur := route.Rule{"mail": {{Provider: "openai", Model: "m"}, {Provider: "anthropic", Model: "c"}}}
	e := newEnv(t, func(c *Config) {
		c.Initial[RoutingPath] = canonicalJSON(cur)
		c.RouteGranted = func(string) bool { return true }
	})
	next := route.Rule{"mail": {{Provider: "anthropic", Model: "c"}, {Provider: "openai", Model: "m"}}}
	ruleCase(e, next, 12)
	rep := e.propose(Candidate{Source: Local, Files: Tree{RoutingPath: canonicalJSON(next)}})
	if rep.State != StateAdopted {
		t.Fatal(rep)
	}
	return e, rep, e.p.Files("routing")
}

// FRJ-1
func TestForgetRevertIsJournaled(t *testing.T) {
	e, rep := forgetEnv(t)
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if got := e.revertsJournaled(rep.ID); len(got) != 1 || got[0] != WhyForgotten {
		t.Fatalf("revert intents: %q", got)
	}
	e.noRevertOnDisk(rep.ID)
	// A second forget journals nothing more.
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if got := e.revertsJournaled(rep.ID); len(got) != 1 {
		t.Fatalf("revert intents after a second forget: %q", got)
	}
}

// FRJ-2
func TestSettingsRevertIsJournaled(t *testing.T) {
	e, rep, was := settingsEnv(t)
	if ok, err := e.p.Superseded("routing", was); err != nil || !ok {
		t.Fatalf("superseded: %v %v", ok, err)
	}
	if got := e.revertsJournaled(rep.ID); len(got) != 1 || got[0] != WhySettings {
		t.Fatalf("revert intents: %q", got)
	}
	e.noRevertOnDisk(rep.ID)
}

// FRJ-3: a body put back to its bytes from before the forget, as a
// restore of the content store would, does not bring the adoption back.
func TestForgetRevertSurvivesARestoredBody(t *testing.T) {
	e, rep := forgetEnv(t)
	before := e.body(rep.ID)
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	e.putBody(rep.ID, before)
	e.reopen()
	if got := e.reverted(rep.ID); got != WhyForgotten {
		t.Fatalf("after a restored body: reverted %q", got)
	}
	if f := e.p.Files("skills"); f["skills/note"] != nil {
		t.Fatalf("the forgotten file is active again: %q", f)
	}
}

// FRJ-3
func TestSettingsRevertSurvivesARestoredBody(t *testing.T) {
	e, rep, was := settingsEnv(t)
	before := e.body(rep.ID)
	if ok, err := e.p.Superseded("routing", was); err != nil || !ok {
		t.Fatalf("superseded: %v %v", ok, err)
	}
	e.putBody(rep.ID, before)
	e.reopen()
	if got := e.reverted(rep.ID); got != WhySettings {
		t.Fatalf("after a restored body: reverted %q", got)
	}
}

// FRJ-3: the process stops after the forget's state save and before its
// intent is journaled. The state owes the record: replay applies it and
// Attach journals it.
func TestOwedRevertJournaledAfterACrash(t *testing.T) {
	e, rep := forgetEnv(t)
	e.p.mu.Lock()
	e.p.j = nil // the journal is unreachable: the record stays owed
	e.p.mu.Unlock()
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if got := e.revertsJournaled(rep.ID); len(got) != 0 {
		t.Fatalf("journaled without a journal: %q", got)
	}
	e.reopen()
	if got := e.reverted(rep.ID); got != WhyForgotten {
		t.Fatalf("owed revert not replayed: %q", got)
	}
	if got := e.revertsJournaled(rep.ID); len(got) != 1 || got[0] != WhyForgotten {
		t.Fatalf("owed revert not journaled at Attach: %q", got)
	}
	e.noRevertOnDisk(rep.ID)
	if raw, _ := e.store.Load(); bytes.Contains(raw, []byte(`"unjournaled"`)) {
		t.Fatal("the state still owes a journaled revert")
	}
	e.reopen()
	if got := e.reverted(rep.ID); got != WhyForgotten {
		t.Fatalf("after the record: reverted %q", got)
	}
	if got := e.revertsJournaled(rep.ID); len(got) != 1 {
		t.Fatalf("journaled twice: %q", got)
	}
}

// FRJ-3: a body an earlier build saved with a forget in it, and no
// intent, is journaled once and leaves the body.
func TestBodyRevertFromAnEarlierBuildIsJournaled(t *testing.T) {
	e, rep := forgetEnv(t)
	old := bytes.Replace(e.body(rep.ID), []byte(`{`), []byte(`{"reverted":"forgotten",`), 1)
	e.putBody(rep.ID, old)
	e.reopen()
	if got := e.reverted(rep.ID); got != WhyForgotten {
		t.Fatalf("earlier build's revert lost: %q", got)
	}
	if got := e.revertsJournaled(rep.ID); len(got) != 1 || got[0] != WhyForgotten {
		t.Fatalf("revert intents: %q", got)
	}
	e.noRevertOnDisk(rep.ID)
}

// FRJ-4: a forgotten or settings revert is only a record of an effect the
// pipeline applied; nobody can submit one to undo an active adoption.
func TestForgedForgetRevertIsDenied(t *testing.T) {
	e, rep := forgetEnv(t)
	for _, c := range []struct{ why, origin, action string }{
		{WhyForgotten, OriginOwner, ActionRevert},
		{WhySettings, OriginOwner, ActionRevert},
		{WhyForgotten, OriginPipeline, ActionRevertAuto},
		{WhySettings, OriginPipeline, ActionRevertAuto},
	} {
		in := journal.Intent{ID: "chg:" + rep.ID + ":revert:n99" + c.origin[:1] + ":" + c.why, Origin: c.origin,
			Account: journal.BrokerAccount, Action: c.action, Executor: Executor,
			Params: map[string]any{"adoption": rep.ID, "why": c.why}}
		if err := e.p.run(bg, in); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("%s/%s: %v", c.why, c.origin, err)
		}
	}
	if got := e.reverted(rep.ID); got != "" {
		t.Fatalf("a forged record reverted the adoption: %q", got)
	}
}

// FRJ-3: the migration saves the debt before it strips the body, so a
// failed save keeps the earlier build's revert in the body, and the next
// start migrates it.
func TestBodyRevertMigrationSurvivesAFailedSave(t *testing.T) {
	e, rep, _ := settingsEnv(t)
	old := bytes.Replace(e.body(rep.ID), []byte(`{`), []byte(`{"reverted":"settings",`), 1)
	e.putBody(rep.ID, old)
	e.p.cfg.Store = &flakyStore{MemStore: e.store, failSave: true}
	e.reopen()
	if !bytes.Contains(e.body(rep.ID), []byte(`"reverted":"settings"`)) {
		t.Fatal("the body lost its revert before the debt was saved")
	}
	e.p.cfg.Store = e.store
	e.reopen()
	if got := e.reverted(rep.ID); got != WhySettings {
		t.Fatalf("earlier build's revert lost: %q", got)
	}
	if got := e.revertsJournaled(rep.ID); len(got) != 1 || got[0] != WhySettings {
		t.Fatalf("revert intents: %q", got)
	}
	e.noRevertOnDisk(rep.ID)
}

// FRJ-4: an owed record (Applied holds its ID) is admitted only from the
// owner origin with meta.change.revert.
func TestOwedRevertWrongOriginIsDenied(t *testing.T) {
	for _, c := range []struct{ origin, action string }{
		{OriginPipeline, ActionRevertAuto},
		{OriginPipeline, ActionRevert},
		{OriginOwner, ActionRevertAuto},
	} {
		e, rep := forgetEnv(t)
		e.p.mu.Lock()
		j := e.p.j
		e.p.j = nil // keep the record owed
		e.p.mu.Unlock()
		if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
			t.Fatal(err)
		}
		e.p.mu.Lock()
		e.p.j = j
		owed := slices.Clone(e.p.st.Unjournaled)
		e.p.mu.Unlock()
		if len(owed) != 1 || !e.p.st.Applied[owed[0]] {
			t.Fatalf("owed: %q", owed)
		}
		in := journal.Intent{ID: owed[0], Origin: c.origin, Account: journal.BrokerAccount,
			Action: c.action, Executor: Executor,
			Params: map[string]any{"adoption": rep.ID, "why": WhyForgotten}}
		if err := e.p.run(bg, in); err == nil || !strings.Contains(err.Error(), "refused") {
			t.Fatalf("%s/%s: %v", c.origin, c.action, err)
		}
	}
}
