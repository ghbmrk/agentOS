package change

import "testing"

// REQ: LOOP-10, CHG-1

// W5a, loops PS1: a Loop 2 regression fixture encodes a finding the
// active tree has now, so the baseline fails it by construction. While it
// does, the fixture only must not regress, and other candidates still
// adopt; once the active tree has passed it, it must pass for good, even
// after the fix is undone.
func TestALoop2FixtureMustNotRegressUntilFirstPassed(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if err := e.p.AddSecurityCase(Case{ID: "loop2/f1", Class: ClassSkill, Input: []byte("skills/fix"), Expect: []byte("yes")}); err != nil {
		t.Fatal(err)
	}
	other := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	if other.State != StateAdopted {
		t.Fatalf("a candidate that leaves the open finding as it is: %+v", other)
	}
	fix := e.propose(Candidate{Source: Local, Files: Tree{"skills/fix": []byte("yes")}})
	if fix.State != StateAdopted {
		t.Fatalf("the fix: %+v", fix)
	}
	// The active tree passed it once: from now on it must pass.
	e.propose(Candidate{Source: Local, Files: Tree{"skills/note": []byte("a")}})
	if err := e.p.Revert(bg, fix.ID, OriginOwner); err != nil {
		t.Fatal(err)
	}
	p, err := New(e.p.cfg) // and it holds across a restart
	if err != nil {
		t.Fatal(err)
	}
	e.p = p
	e.p.Attach(e.eng)
	if r := e.propose(Candidate{Source: Local, Files: Tree{"skills/note": []byte("b")}}); r.State != StateRejected || r.Reason != "fails the security suite" {
		t.Fatalf("after the fix was undone: %+v", r)
	}
}

// Any other security fixture must pass, whatever the baseline does.
func TestOtherSecurityFixturesMustPass(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if err := e.p.AddSecurityCase(Case{ID: "sec-open", Class: ClassSkill, Input: []byte("skills/fix"), Expect: []byte("yes")}); err != nil {
		t.Fatal(err)
	}
	if r := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}}); r.State != StateRejected {
		t.Fatalf("%+v", r)
	}
}

// Potency C1 on W5a: the must-pass switch is per fixture. Of two open
// findings only the fixed one must pass from then on, across a restart;
// the other still only must not regress.
func TestTheMustPassSwitchIsPerFixture(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	for _, c := range []Case{
		{ID: "loop2/a", Class: ClassSkill, Input: []byte("skills/fix-a"), Expect: []byte("yes")},
		{ID: "loop2/b", Class: ClassSkill, Input: []byte("skills/fix-b"), Expect: []byte("yes")},
	} {
		if err := e.p.AddSecurityCase(c); err != nil {
			t.Fatal(err)
		}
	}
	fix := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), "skills/fix-a": []byte("yes")}})
	if fix.State != StateAdopted {
		t.Fatalf("the fix for a: %+v", fix)
	}
	e.propose(Candidate{Source: Local, Files: Tree{"skills/note": []byte("1")}}) // the active tree passes a
	p, err := New(e.p.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.p = p
	e.p.Attach(e.eng)
	// The restarted pipeline evaluates on the old journal, so scores are
	// what count here, not adoption.
	if r := e.propose(Candidate{Source: Local, Files: Tree{"skills/note": []byte("2")}}); r.Reason == "fails the security suite" || r.SecurityPassed != r.Security {
		t.Fatalf("b, still open, failed a candidate: %+v", r)
	}
	if r := e.propose(Candidate{Source: Local, Files: Tree{"skills/fix-a": []byte("no")}}); r.State != StateRejected || r.Reason != "fails the security suite" {
		t.Fatalf("a regressed: %+v", r)
	}
}

// Security L4 on W5a: the mark is keyed by the fixture's contents, so a
// fixture replaced under the same ID is open again.
func TestTheMustPassMarkFollowsTheFixturesContents(t *testing.T) {
	a := Case{ID: "loop2/a", Input: []byte("in"), Expect: []byte("yes")}
	b := a
	b.Expect = []byte("yes, at 3.1")
	if loop2Key(a) == loop2Key(b) || loop2Key(a) != loop2Key(a) {
		t.Fatal("the mark key does not follow the contents")
	}
}

// Security L3 on W5a: no candidate can add, change or delete a Loop 2
// fixture. Fixtures are not files in the tree, and a candidate writing a
// path named for them is rejected before evaluation.
func TestACandidateCannotTouchLoop2Fixtures(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	for _, path := range []string{"loop2/a", "security/loop2/a", "suites/loop2/a"} {
		r := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), path: []byte("x")}})
		if r.State != StateRejected {
			t.Fatalf("%s: %+v", path, r)
		}
	}
}
