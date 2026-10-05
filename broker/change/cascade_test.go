package change

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// REQ: CAP-3, CHG-1

// W3-tasks part 2 (security C1 on #120): Loop 1 marks a candidate with the
// goals of the owner tasks its builder read. Forgetting one of them undoes
// the adoption at once, with no intent and no second approval (the
// owner's deletion, as C18), and its file contents leave the pipeline's
// saved state, history included. The live target gets the tree without it.
func TestForgetGoalUndoesWhatWasLearnedFromIt(t *testing.T) {
	tg := &fakeTarget{ns: "skills"}
	e := newEnv(t, func(c *Config) { c.Targets = map[string]Target{"skills": tg} })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	rep := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": []byte("CANARY-g1")}})
	if rep.State != StateAdopted {
		t.Fatalf("setup: %+v", rep)
	}
	other := e.propose(Candidate{Source: Local, Goals: []string{"owner:g2"}, Files: Tree{"skills/other": []byte("kept")}})
	if other.State != StateAdopted {
		t.Fatalf("setup: %+v", other)
	}
	e.p.Digest()
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	files := e.p.Files("skills")
	if string(files["skills/greet"]) != "hi" || files["skills/note"] != nil || string(files["skills/other"]) != "kept" {
		t.Fatalf("active tree after the forget: %q", files)
	}
	if tg.applied["skills/note"] != nil || string(tg.applied["skills/greet"]) != "hi" || string(tg.applied["skills/other"]) != "kept" {
		t.Fatalf("live target after the forget: %q", tg.applied)
	}
	raw, err := e.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("CANARY")) || bytes.Contains(raw, []byte("Q0FOQVJZ")) { // base64 of "CANARY"
		t.Fatal("the saved state still holds the forgotten goal's files")
	}
	var undone *Adoption
	for _, a := range e.p.Adoptions() {
		if a.ID == rep.ID {
			undone = &a
		}
		if a.ID == other.ID && a.Reverted != "" {
			t.Fatal("another goal's adoption was undone")
		}
	}
	if undone == nil || undone.Reverted != WhyForgotten {
		t.Fatalf("forgotten adoption: %+v", undone)
	}
	want := "Undid " + rep.Short + ": it was learned from a task you asked the box to forget."
	if d := strings.Join(e.p.Digest(), "\n"); !strings.Contains(d, want) {
		t.Fatalf("digest %q lacks %q", d, want)
	}
	if err := e.p.Revert(bg, rep.ID, OriginOwner); err == nil {
		t.Fatal("UNDO of a forgotten adoption succeeded")
	}
	// A second forget finds nothing more.
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
}

// A later adoption that changed a file the forgotten one wrote keeps its
// own content, and its UNDO now goes back to the file as it was before the
// forgotten adoption, so its history no longer holds the forgotten file.
func TestForgetGoalRewritesALaterAdoptionsUndo(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": []byte("CANARY-g1")}})
	b := e.propose(Candidate{Source: Local, Goals: []string{"owner:g2"}, Files: Tree{"skills/note": []byte("plain")}})
	if a.State != StateAdopted || b.State != StateAdopted {
		t.Fatalf("setup: %+v %+v", a, b)
	}
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	files := e.p.Files("skills")
	if string(files["skills/greet"]) != "hi" || string(files["skills/note"]) != "plain" {
		t.Fatalf("active tree: %q", files)
	}
	if raw, _ := e.store.Load(); bytes.Contains(raw, []byte("Q0FOQVJZ")) {
		t.Fatal("the later adoption's history still holds the forgotten file")
	}
	if err := e.p.Revert(bg, b.ID, OriginOwner); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.p.Files("skills")["skills/note"]; ok {
		t.Fatal("UNDO of the later adoption did not go back to before the forgotten one")
	}
}

// L3 MUST-1 on #160: a later adoption's UNDO is rewritten only where it
// built on the forgotten file, by succession, not where another adoption
// wrote the same bytes. a (undone) and c both wrote v1; d built on c's.
func TestForgetGoalFollowsSuccessionNotBytes(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": []byte("v1")}})
	if a.State != StateAdopted {
		t.Fatalf("setup: %+v", a)
	}
	if err := e.p.Revert(bg, a.ID, OriginOwner); err != nil {
		t.Fatal(err)
	}
	c := e.propose(Candidate{Source: Local, Goals: []string{"owner:g2"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": []byte("v1")}})
	d := e.propose(Candidate{Source: Local, Goals: []string{"owner:g3"}, Files: Tree{"skills/note": []byte("v3")}})
	if c.State != StateAdopted || d.State != StateAdopted {
		t.Fatalf("setup: %+v %+v", c, d)
	}
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Revert(bg, d.ID, OriginOwner); err != nil {
		t.Fatal(err)
	}
	if got := string(e.p.Files("skills")["skills/note"]); got != "v1" {
		t.Fatalf("UNDO of d left %q, want c's v1", got)
	}
	if err := e.p.Revert(bg, c.ID, OriginOwner); err != nil {
		t.Fatal(err)
	}
	if files := e.p.Files("skills"); files["skills/note"] != nil || string(files["skills/greet"]) != "hi" {
		t.Fatalf("UNDO of c left %q", files)
	}
}

// An undone later adoption kept the forgotten file as its own Before; it
// goes too, and the next active one still goes back past it, though the
// file it built on reached it through the undo.
func TestForgetGoalPassesAnUndoneSuccessor(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": []byte("CANARY-g1")}})
	b := e.propose(Candidate{Source: Local, Goals: []string{"owner:g2"}, Files: Tree{"skills/note": []byte("v2")}})
	if a.State != StateAdopted || b.State != StateAdopted {
		t.Fatalf("setup: %+v %+v", a, b)
	}
	if err := e.p.Revert(bg, b.ID, OriginOwner); err != nil {
		t.Fatal(err)
	}
	c := e.propose(Candidate{Source: Local, Goals: []string{"owner:g3"}, Files: Tree{"skills/note": []byte("v3")}})
	if c.State != StateAdopted {
		t.Fatalf("setup: %+v", c)
	}
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if files := e.p.Files("skills"); string(files["skills/note"]) != "v3" || string(files["skills/greet"]) != "hi" {
		t.Fatalf("active tree: %q", files)
	}
	if raw, _ := e.store.Load(); bytes.Contains(raw, []byte("Q0FOQVJZ")) {
		t.Fatal("history still holds the forgotten file")
	}
	if err := e.p.Revert(bg, c.ID, OriginOwner); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.p.Files("skills")["skills/note"]; ok {
		t.Fatal("UNDO of c did not go back past the forgotten file")
	}
}

// An adoption the owner already undid still kept its files in history;
// the forget removes them there too and leaves the active tree alone,
// even where a later adoption wrote the same content.
func TestForgetGoalScrubsAnUndoneAdoption(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": []byte("CANARY-g1")}})
	if a.State != StateAdopted {
		t.Fatalf("setup: %+v", a)
	}
	if err := e.p.Revert(bg, a.ID, OriginOwner); err != nil {
		t.Fatal(err)
	}
	// Another goal's adoption later writes the same greeting; it stays.
	if b := e.propose(Candidate{Source: Local, Goals: []string{"owner:g2"}, Files: Tree{"skills/greet": []byte("hello")}}); b.State != StateAdopted {
		t.Fatalf("setup: %+v", b)
	}
	before := e.p.Files("skills")
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if raw, _ := e.store.Load(); bytes.Contains(raw, []byte("Q0FOQVJZ")) {
		t.Fatal("history still holds the undone adoption's files")
	}
	if after := e.p.Files("skills"); after.Hash() != before.Hash() {
		t.Fatalf("active tree changed: %q", after)
	}
	for _, ad := range e.p.Adoptions() {
		if ad.ID == a.ID && ad.Reverted != WhyOwner {
			t.Fatalf("the owner's UNDO became %q", ad.Reverted)
		}
	}
}

// A candidate built from a forgotten goal is never adopted: not when it is
// proposed after the forget (refused before any evaluation spend), and not
// when its evaluation was running as the forget came in.
func TestAForgottenGoalsCandidateIsNotAdopted(t *testing.T) {
	var once sync.Once
	var e *env
	runs := 0
	e = newEnv(t, func(c *Config) {
		ev := c.Evaluator
		c.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
			runs++
			if string(tr["skills/note"]) == "CANARY-g1" {
				once.Do(func() {
					if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
						t.Error(err)
					}
				})
			}
			return ev.Run(ctx, tr, pr)
		})
	})
	e.cases(12, ClassSkill, "skills/greet", "hello")
	cand := Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": []byte("CANARY-g1")}}
	if _, err := e.p.Propose(bg, cand); !errors.Is(err, ErrForgotten) {
		t.Fatalf("in flight across the forget: %v", err)
	}
	runs = 0
	if _, err := e.p.Propose(bg, cand); !errors.Is(err, ErrForgotten) || runs != 0 {
		t.Fatalf("after the forget: %v, %d probes run", err, runs)
	}
	if len(e.p.Adoptions()) != 0 || e.p.Files("skills")["skills/note"] != nil {
		t.Fatal("a forgotten goal's candidate was adopted")
	}
}

// A proposal waiting for the owner when its goal is forgotten is dropped:
// the owner's later YES adopts nothing.
func TestAWaitingProposalGoesWithItsGoal(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if err := e.p.SetAutoAdopt(bg, false); err != nil {
		t.Fatal(err)
	}
	e.p.Attach(holdJournal{e.eng})
	e.owner.approve = true
	rep := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": []byte("CANARY-g1")}})
	if rep.State != StateAwaitingOwner || !e.p.Waiting(rep.ID) {
		t.Fatalf("setup: %+v", rep)
	}
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if e.p.Waiting(rep.ID) {
		t.Fatal("the proposal still waits")
	}
	if _, err := e.eng.Authorize(bg, adoptID(rep.ID)); err != nil {
		t.Fatal(err)
	}
	if r, err := e.p.Settle(bg, rep.ID); err == nil && r.State == StateAdopted {
		t.Fatal("the owner's YES adopted a forgotten goal's candidate")
	}
	if e.p.Files("skills")["skills/note"] != nil {
		t.Fatal("adopted")
	}
}

// Security R1 on #123 for the cascade: a forget whose save failed reports
// it and leaves the saved state as it was; the retry undoes and saves.
func TestForgetGoalCascadeRetriesAFailedSave(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/note": []byte("CANARY-g1")}})
	if a.State != StateAdopted {
		t.Fatalf("setup: %+v", a)
	}
	e.store.Fail = errors.New("disk full")
	if _, err := e.p.ForgetGoal("owner:g1"); err == nil {
		t.Fatal("forget reported done with its save failing")
	}
	e.store.Fail = nil
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if raw, _ := e.store.Load(); bytes.Contains(raw, []byte("Q0FOQVJZ")) {
		t.Fatal("the retried forget left the files saved")
	}
	if e.p.Files("skills")["skills/note"] != nil {
		t.Fatal("still active")
	}
}

// downStore can neither save nor load.
type downStore struct{}

func (downStore) Load() ([]byte, error) { return nil, errors.New("disk gone") }
func (downStore) Save([]byte) error     { return errors.New("disk gone") }

// A forget whose save and reload both failed leaves the pipeline broken:
// every later forget is refused, even once the disk is back, until a
// restart reads the saved state again.
func TestForgetGoalRefusedOnceBroken(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"}, Files: Tree{"skills/greet": []byte("hello")}}); a.State != StateAdopted {
		t.Fatalf("setup: %+v", a)
	}
	store := e.p.cfg.Store
	e.p.cfg.Store = downStore{}
	if _, err := e.p.ForgetGoal("owner:g1"); err == nil {
		t.Fatal("forget reported done with no disk")
	}
	e.p.cfg.Store = store
	if _, err := e.p.ForgetGoal("owner:g1"); err == nil || !strings.Contains(err.Error(), "restart needed") {
		t.Fatalf("forget on a broken pipeline: %v", err)
	}
}

// MORE on a forgotten adoption names its files as forgotten, not new.
func TestMoreSaysForgotten(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"}, Files: Tree{"skills/greet": []byte("hello")}})
	if a.State != StateAdopted {
		t.Fatalf("setup: %+v", a)
	}
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	lines, err := e.p.More(a.Short)
	if err != nil || !strings.Contains(lines[0], "skills/greet (forgotten)") {
		t.Fatalf("MORE: %q %v", lines, err)
	}
}

// An empty file is a file: forgetting the adoption that created it as
// empty removes it, rather than leaving it empty.
func TestForgetGoalTellsAnEmptyFileFromNone(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/empty": {}}})
	if a.State != StateAdopted {
		t.Fatalf("setup: %+v", a)
	}
	if _, ok := e.p.Files("skills")["skills/empty"]; !ok {
		t.Fatal("setup: the empty file was not adopted")
	}
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.p.Files("skills")["skills/empty"]; ok {
		t.Fatal("the forgotten adoption's empty file stayed")
	}
}

// Only what Loop 1 builds carries goals: a candidate learned from owner
// tasks that reaches past skills, procedures and context is rejected
// before evaluation, so a forget never undoes a setting or an image.
func TestALearnedCandidateStaysInLearnedClasses(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	rep := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "config/x": []byte("1")}})
	if rep.State != StateRejected || !strings.Contains(rep.Reason, "only skills, procedures and context") {
		t.Fatalf("report: %+v", rep)
	}
	if ok := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "context/agent.json": []byte(`{"select":[]}`)}}); ok.State == StateRejected && strings.Contains(ok.Reason, "only skills") {
		t.Fatalf("context refused: %+v", ok)
	}
}

// L3 MUST-A on #160: a live delete whose Before went back past a
// forgotten file holds nothing either side, like a cleared edit, but is
// still the delete. w writes x, z deletes it, a writes it again, b deletes
// it; forgetting a then z leaves x deleted by b, and UNDO b brings back
// w's x, as if neither forgotten adoption had happened.
func TestForgetGoalKeepsALiveDeleteThatHoldsNothing(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	w := e.propose(Candidate{Source: Local, Goals: []string{"owner:g0"}, Files: Tree{"skills/greet": []byte("hello"), "skills/x": []byte("v5")}})
	z := e.propose(Candidate{Source: Local, Goals: []string{"owner:g2"}, Delete: []string{"skills/x"}})
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"}, Files: Tree{"skills/x": []byte("CANARY-g1")}})
	b := e.propose(Candidate{Source: Local, Goals: []string{"owner:g3"}, Delete: []string{"skills/x"}})
	for _, r := range []Report{w, z, a, b} {
		if r.State != StateAdopted {
			t.Fatalf("setup: %+v", r)
		}
	}
	for _, g := range []string{"owner:g1", "owner:g2"} {
		if _, err := e.p.ForgetGoal(g); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := e.p.Files("skills")["skills/x"]; ok {
		t.Fatal("b's delete was undone by the forgets")
	}
	if more, _ := e.p.More(b.Short); strings.Contains(more[0], "forgotten") {
		t.Fatalf("MORE b: %q", more)
	}
	if err := e.p.Revert(bg, b.ID, OriginOwner); err != nil {
		t.Fatal(err)
	}
	if got := string(e.p.Files("skills")["skills/x"]); got != "v5" {
		t.Fatalf("UNDO b left %q, want w's v5", got)
	}
}

// A later adoption still active that wrote the forgotten adoption's bytes
// again keeps the file: b changed it, c wrote a's bytes back. The forget
// leaves c's file, and UNDO b goes back to before a.
func TestForgetGoalLeavesAFileALaterAdoptionWroteBack(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"}, Files: Tree{"skills/greet": []byte("hello"), "skills/note": []byte("v1")}})
	b := e.propose(Candidate{Source: Local, Goals: []string{"owner:g2"}, Files: Tree{"skills/note": []byte("v2")}})
	c := e.propose(Candidate{Source: Local, Goals: []string{"owner:g3"}, Files: Tree{"skills/note": []byte("v1")}})
	for _, r := range []Report{a, b, c} {
		if r.State != StateAdopted {
			t.Fatalf("setup: %+v", r)
		}
	}
	if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if got := string(e.p.Files("skills")["skills/note"]); got != "v1" {
		t.Fatalf("c's file became %q", got)
	}
	for _, id := range []string{c.ID, b.ID} {
		if err := e.p.Revert(bg, id, OriginOwner); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := e.p.Files("skills")["skills/note"]; ok {
		t.Fatal("UNDO b did not go back to before a")
	}
}

// SHOULD-A on #160: an empty file stays an empty file across a restart,
// so a forget after one still removes the file the adoption created.
func TestAnEmptyFileSurvivesARestart(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"},
		Files: Tree{"skills/greet": []byte("hello"), "skills/empty": {}}})
	if a.State != StateAdopted {
		t.Fatalf("setup: %+v", a)
	}
	p, err := New(e.p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ForgetGoal("owner:g1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Files("skills")["skills/empty"]; ok {
		t.Fatal("after a restart, the forget left the empty file")
	}
}

// Recheck reads an adoption again after evaluating it: one a forget undid
// meanwhile is skipped, not reverted a second time.
func TestRecheckSkipsAnAdoptionForgottenMeanwhile(t *testing.T) {
	var armed bool
	var e *env
	e = newEnv(t, func(c *Config) {
		ev := c.Evaluator
		c.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
			if armed {
				armed = false
				if _, err := e.p.ForgetGoal("owner:g1"); err != nil {
					t.Error(err)
				}
			}
			return ev.Run(ctx, tr, pr)
		})
	})
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"owner:g1"}, Files: Tree{"skills/greet": []byte("hello")}})
	if a.State != StateAdopted {
		t.Fatalf("setup: %+v", a)
	}
	e.p.AddSecurityCase(Case{ID: "sec-2", Class: ClassSkill, Input: []byte("skills/greet"), Expect: []byte("hi")})
	armed = true
	ids, err := e.p.Recheck(bg)
	if err != nil || len(ids) != 0 {
		t.Fatalf("Recheck: %v %v", ids, err)
	}
}
