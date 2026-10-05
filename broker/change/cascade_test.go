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
