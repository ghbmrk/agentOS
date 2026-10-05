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
