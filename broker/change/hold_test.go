package change

import (
	"errors"
	"testing"
)

// REQ: LOOP-9, LOOP-10, CHG-2

// holdRule is a tree rule over skills/greet, which the env tree holds as
// "hi" (not JSON), so only an empty-pointer absent clause can hold.
func holdRule(op string) []byte {
	return TreeRule{Clauses: []Clause{{Path: "skills/greet", Op: op}}}.Encode()
}

// P3-4b-1b item 1: LinkedHold answers every case linked to a finding from
// the active tree alone. It holds only when at least one case is linked
// and every one of them passes; a linked case that is not a tree rule
// cannot be answered without a run, so it never holds (fail closed).
func TestLinkedHoldAnswersAFindingsCasesFromTheActiveTree(t *testing.T) {
	e := linkEnv(t)
	if n, ok := e.p.LinkedHold("H1"); n != 0 || ok {
		t.Fatalf("no linked case: %d %v", n, ok)
	}
	pass := Case{ID: "loop2/H1", Input: TreeRule{}.Encode(), Expect: []byte(TreeRuleOK), Finding: "H1"}
	if err := e.p.AddSecurityCase(pass); err != nil {
		t.Fatal(err)
	}
	if n, ok := e.p.LinkedHold("H1"); n != 1 || !ok {
		t.Fatalf("one passing case: %d %v", n, ok)
	}
	fail := Case{ID: "held/H1/v1", Input: holdRule(OpAbsent), Expect: []byte(TreeRuleOK), Finding: "H1"}
	if err := e.p.AddSecurityCase(fail); err != nil {
		t.Fatal(err)
	}
	if n, ok := e.p.LinkedHold("H1"); n != 2 || ok {
		t.Fatalf("a failing linked case: %d %v", n, ok)
	}
	plain := Case{ID: "loop2/H2", Input: []byte("skills/greet"), Expect: []byte("hello"), Finding: "H2"}
	if err := e.p.AddSecurityCase(plain); err != nil {
		t.Fatal(err)
	}
	if n, ok := e.p.LinkedHold("H2"); n != 1 || ok {
		t.Fatalf("a plain linked case: %d %v", n, ok)
	}
	if n, ok := e.p.LinkedHold(""); n != 0 || ok {
		t.Fatalf("no finding: %d %v", n, ok)
	}
}

// P3-4b-1b item 2: adding a security case under an ID the suite already
// holds is ErrDuplicate; when the stored case differs in input, expect or
// finding it is also ErrConflict, so a caller can tell another finding's
// case from its own.
func TestAConflictingSecurityCaseIsNotADuplicateOfItsOwn(t *testing.T) {
	e := linkEnv(t)
	before := e.p.SecurityCount()
	c := Case{ID: "loop2/X/original", Input: TreeRule{}.Encode(), Expect: []byte(TreeRuleOK), Finding: "X/original"}
	if err := e.p.AddSecurityCase(c); err != nil {
		t.Fatal(err)
	}
	if err := e.p.AddSecurityCase(c); !errors.Is(err, ErrDuplicate) || errors.Is(err, ErrConflict) {
		t.Fatalf("same case again: %v", err)
	}
	for name, mod := range map[string]func(*Case){
		"input":   func(d *Case) { d.Input = holdRule(OpAbsent) },
		"expect":  func(d *Case) { d.Expect = []byte(TreeRuleFail) },
		"finding": func(d *Case) { d.Finding = "X" },
	} {
		d := c
		mod(&d)
		if err := e.p.AddSecurityCase(d); !errors.Is(err, ErrDuplicate) || !errors.Is(err, ErrConflict) {
			t.Fatalf("%s differs: %v", name, err)
		}
	}
	if n := e.p.SecurityCount(); n != before+1 {
		t.Fatalf("suite holds %d security cases", n)
	}
}
