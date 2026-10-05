package change

// Wiring support for the grants gate (C7, C8) and #34's optional nits.
// REQ: CHG-1, CHG-2, CHG-3, CHG-6, LOOP-10

import (
	"context"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
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

// C8: the owner line for each change that needs the owner is broker text
// that fits CH-12's fields.
func TestOwnerLine(t *testing.T) {
	e := newEnv(t, nil)
	e.p.Attach(holdJournal{e.eng})
	r := e.propose(Candidate{Source: Local, Files: Tree{"skills/n": []byte("x")}, Claim: "trust me"})
	if r.State != StateAwaitingOwner {
		t.Fatal(r)
	}
	st, err := e.eng.Get(adoptID(r.ID))
	if err != nil {
		t.Fatal(err)
	}
	l, err := e.p.line(st.Intent)
	if err != nil || l != (ownerLine{Verb: "adopt", Object: "a learned skill, not tested yet", Undoable: true}) {
		t.Fatalf("%+v %v", l, err)
	}
	for _, c := range []struct {
		in   journal.Intent
		want ownerLine
	}{
		{journal.Intent{ID: "chg:policy:n9:auto_adopt:on", Action: ActionPolicy}, ownerLine{Verb: "turn on", Object: "learning without asking", Undoable: true}},
		{journal.Intent{ID: "chg:policy:n9:sharing:on", Action: ActionPolicy}, ownerLine{Verb: "turn on", Object: "sharing learned changes", Undoable: true}},
		{journal.Intent{ID: "chg:suite:n9:remove:case-1", Action: ActionSuite}, ownerLine{Verb: "remove", Object: "a past task from the tests"}},
	} {
		if l, err := e.p.line(c.in); err != nil || l != c.want {
			t.Fatalf("%s: %+v %v", c.in.ID, l, err)
		}
	}
	if _, err := e.p.line(journal.Intent{ID: "chg:c999:adopt", Action: ActionAdopt}); err == nil {
		t.Fatal("a line for no proposal")
	}
}

// C7: a request that closes without the owner's answer drops the proposal
// and records no decline; only the owner's no is a decline.
func TestDecidedDropsUnansweredWithoutDecline(t *testing.T) {
	e := newEnv(t, nil)
	e.p.Attach(holdJournal{e.eng})
	r := e.release(release(t, "3.0", true, map[string][]byte{"host-image/release": []byte("h")}))
	if r.State != StateAwaitingOwner {
		t.Fatal(r)
	}
	st, _ := e.eng.Get(adoptID(r.ID))
	e.p.Decided(bg, st.Intent) // still pending: the request lapsed
	if _, err := e.p.Settle(bg, r.ID); err == nil {
		t.Fatal("a lapsed proposal was kept")
	}
	if d := e.p.Digest(); len(d) != 0 {
		t.Fatalf("a lapsed request reads as a decline: %q", d)
	}
	if err := e.p.Check(bg, journal.PhaseAuthorize, st.Intent); err == nil || strings.Contains(err.Error(), "owner") {
		t.Fatalf("a dropped proposal's intent is still approvable: %v", err)
	}

	r = e.release(release(t, "3.1", true, map[string][]byte{"host-image/release": []byte("i")}))
	e.eng.Authorize(bg, adoptID(r.ID)) // the owner says no
	st, _ = e.eng.Get(adoptID(r.ID))
	if st.State != journal.Denied {
		t.Fatal(st.State)
	}
	e.p.Decided(bg, st.Intent)
	if d := e.p.Digest(); len(d) != 1 || !strings.HasPrefix(d[0], "You declined security update 3.1;") {
		t.Fatalf("%q", d)
	}
}
