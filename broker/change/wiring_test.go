package change

// Wiring support for the grants gate (C7, C8) and #34's optional nits.
// REQ: CHG-1, CHG-2, CHG-3, CHG-6, LOOP-10

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// #34 nit: a change with no classes is judged strictly, so a declined
// held-out case is a fail rather than "not tested".
func TestStrictForEmptyClasses(t *testing.T) {
	for _, src := range []Source{Local, Shared, Upstream} {
		if !strictFor(src, nil).heldOut {
			t.Fatalf("%s with no classes is lenient on held-out cases", src)
		}
	}
	if strictFor(Upstream, []Class{ClassHostImage}).heldOut {
		t.Fatal("an image may still be not evaluated on this box")
	}
}

// #34 nit, LOOP-10: Recheck reverts an adoption whose tree the evaluator
// now declines while the tree without it evaluates (C5).
func TestRecheckRevertsDeclinedTree(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), "skills/y": []byte("ok")}})
	if a.State != StateAdopted {
		t.Fatal(a)
	}
	ev := e.p.cfg.Evaluator
	e.p.cfg.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
		if _, ok := tr["skills/y"]; ok {
			return nil, ErrNotEvaluated
		}
		return ev.Run(ctx, tr, pr)
	})
	ids, err := e.p.Recheck(bg)
	if err != nil || len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("a declined tree was not reverted: %v %v", ids, err)
	}
	if _, ok := e.p.Files("skills")["skills/y"]; ok {
		t.Fatal("the declined skill is still active")
	}
}

// C8, CH-12 (UX and arbitrator on #48): the owner item for each change
// that needs the owner is broker text; the test result rides in Detail so
// the object cap never cuts it; only a tested, undoable, local learned
// skill or procedure is low tier.
func TestOwnerLine(t *testing.T) {
	e := newEnv(t, nil)
	e.p.Attach(holdJournal{e.eng})
	item := func(r Report) owner.Item {
		t.Helper()
		st, err := e.eng.Get(adoptID(r.ID))
		if err != nil {
			t.Fatal(err)
		}
		it, err := e.p.Line(st.Intent)
		if err != nil {
			t.Fatal(err)
		}
		return it
	}
	high := func(verb, obj, detail, undo string) owner.Item {
		return owner.Item{Object: obj, Detail: detail, UndoBy: undo, Facts: owner.Facts{Kind: owner.GrantChange, Verb: verb, NoRecipient: true}}
	}
	r := e.propose(Candidate{Source: Local, Files: Tree{"skills/n": []byte("x")}, Claim: "trust me"})
	if got := item(r); got != high("adopt", "a learned skill", "not tested on past tasks yet", "can be undone later") {
		t.Fatalf("untested: %+v", got)
	}
	e.cases(12, ClassSkill, "skills/greet", "hello")
	r = e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	low := owner.Item{Object: "a learned skill", Detail: "tested on " + itoa(r.HeldOut) + " past tasks, none worse", UndoBy: "can be undone later",
		Facts: owner.Facts{Kind: owner.Ordinary, Verb: "adopt", NoRecipient: true}}
	if got := item(r); r.HeldOut == 0 || got != low {
		t.Fatalf("tested: %+v", got)
	}

	ev := e.p.cfg.Evaluator
	e = newEnv(t, nil)
	e.p.Attach(holdJournal{e.eng})
	e.cases(12, ClassSkill, "skills/greet", "hi")
	ev = e.p.cfg.Evaluator
	e.p.cfg.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
		if _, ok := tr["host-image/release"]; ok && string(pr.Input) != exfilProbe {
			return []byte("worse"), nil
		}
		return ev.Run(ctx, tr, pr)
	})
	long := int64(math.MaxInt64)
	r = e.release(release(t, long, true, map[string][]byte{"host-image/release": []byte("h")}))
	got := item(r)
	if r.Regressions == 0 || got.Detail != "worse on "+itoa(r.Regressions)+" of "+itoa(r.HeldOut)+" past tasks" ||
		got.Facts.Kind != owner.GrantChange || got.UndoBy != "" || len(got.Object) > 40 {
		t.Fatalf("release: %+v %+v", r, got)
	}

	for _, c := range []struct {
		in   journal.Intent
		want owner.Item
	}{
		{journal.Intent{ID: "chg:policy:n9:auto_adopt:on", Action: ActionPolicy}, high("turn on", "learning without asking", "", "LEARN OFF any time")},
		{journal.Intent{ID: "chg:policy:n9:sharing:on", Action: ActionPolicy}, high("turn on", "sharing learned changes", "", "can be undone later")},
		{journal.Intent{ID: "chg:suite:n9:remove:nope", Action: ActionSuite}, high("remove", "a past task from the tests", "", "")},
		{journal.Intent{ID: "chg:suite:n9:remove:sec-1", Action: ActionSuite}, high("remove", "a security check from the tests", "", "")},
	} {
		if l, err := e.p.Line(c.in); err != nil || l != c.want {
			t.Fatalf("%s: %+v %v", c.in.ID, l, err)
		}
	}
	if _, err := e.p.Line(journal.Intent{ID: "chg:c999:adopt", Action: ActionAdopt}); err == nil {
		t.Fatal("a line for no proposal")
	}
}

// C7: a request that closes without the owner's answer drops the proposal
// and records no decline; only the owner's no is a decline.
func TestDecidedDropsUnansweredWithoutDecline(t *testing.T) {
	e := newEnv(t, nil)
	e.p.Attach(holdJournal{e.eng})
	r := e.release(release(t, 30, true, map[string][]byte{"host-image/release": []byte("h")}))
	if r.State != StateAwaitingOwner {
		t.Fatal(r)
	}
	st, _ := e.eng.Get(adoptID(r.ID))
	e.p.Decided(bg, st.Intent, false) // still pending: the request lapsed
	if _, err := e.p.Settle(bg, r.ID); err == nil {
		t.Fatal("a lapsed proposal was kept")
	}
	if d := e.p.Digest(); len(d) != 0 {
		t.Fatalf("a lapsed request reads as a decline: %q", d)
	}
	if err := e.p.Check(bg, journal.PhaseAuthorize, st.Intent); err == nil || strings.Contains(err.Error(), "owner") {
		t.Fatalf("a dropped proposal's intent is still approvable: %v", err)
	}

	r = e.release(release(t, 31, true, map[string][]byte{"host-image/release": []byte("i")}))
	e.eng.Authorize(bg, adoptID(r.ID)) // the owner says no
	st, _ = e.eng.Get(adoptID(r.ID))
	if st.State != journal.Denied {
		t.Fatal(st.State)
	}
	e.p.Decided(bg, st.Intent, true)
	if d := e.p.Digest(); len(d) != 1 || !strings.HasPrefix(d[0], "You declined security update 31;") {
		t.Fatalf("%q", d)
	}
}

// UPD-5 (P2-2a f3): a release dropped because its request closed without
// the owner's answer is reported to Loop 3 once, so the next update check
// offers it again; one the owner declined is not.
func TestDecidedLapsedReleaseReportedOnce(t *testing.T) {
	// REQ: UPD-5
	e := newEnv(t, nil)
	e.p.Attach(holdJournal{e.eng})
	r := e.release(release(t, 30, true, map[string][]byte{"host-image/release": []byte("h")}))
	if r.State != StateAwaitingOwner || e.p.Lapsed(r.ID) {
		t.Fatalf("lapsed before the request closed: %+v", r)
	}
	st, _ := e.eng.Get(adoptID(r.ID))
	e.p.Decided(bg, st.Intent, false) // the request expired unanswered
	if !e.p.Lapsed(r.ID) {
		t.Fatal("a lapsed release is not reported")
	}
	if e.p.Lapsed(r.ID) {
		t.Fatal("a lapsed release is reported twice")
	}

	r = e.release(release(t, 31, true, map[string][]byte{"host-image/release": []byte("i")}))
	e.eng.Authorize(bg, adoptID(r.ID)) // the owner says no
	st, _ = e.eng.Get(adoptID(r.ID))
	e.p.Decided(bg, st.Intent, true)
	if e.p.Waiting(r.ID) || e.p.Lapsed(r.ID) {
		t.Fatal("the owner's no reads as a lapse")
	}
	if e.p.Lapsed("c999") {
		t.Fatal("an unknown proposal reads as lapsed")
	}
}
