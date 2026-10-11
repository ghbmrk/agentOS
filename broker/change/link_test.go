package change

import (
	"strings"
	"testing"
)

// REQ: LOOP-10, CHG-2, A11

// linkEnv has an open finding F1 with its regression and one held-back
// case linked to it by someone other than Loop 2 (the A11 harness).
func linkEnv(t *testing.T) *env {
	t.Helper()
	// The tree holds one governance file, so a delete of it is an edit.
	e := newEnv(t, func(c *Config) { c.Initial["suites/readme"] = []byte("cases live in the pipeline") })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	for _, c := range []Case{
		{ID: "loop2/F1", Class: ClassSkill, Input: []byte("skills/fix"), Expect: []byte("yes"), Finding: "F1"},
		{ID: "held/F1/v1", Class: ClassSkill, Input: []byte("skills/fix2"), Expect: []byte("yes"), Finding: "F1"},
	} {
		if err := e.p.AddSecurityCase(c); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// P3-4b item 4: a fix for F qualifies only if every case linked to F
// passes, the held-back one included (6(g)).
func TestAFixMustPassEveryCaseLinkedToItsFinding(t *testing.T) {
	e := linkEnv(t)
	r := e.propose(Candidate{Source: Local, Finding: "F1", Files: Tree{"skills/greet": []byte("hello"), "skills/fix": []byte("yes")}})
	if r.State != StateRejected || r.Reason != ReasonLinked {
		t.Fatalf("passes the visible regression only: %+v", r)
	}
	r = e.propose(Candidate{Source: Local, Finding: "F1", Files: Tree{"skills/greet": []byte("hello"), "skills/fix": []byte("yes"), "skills/fix2": []byte("yes")}})
	if r.State != StateAdopted || r.Linked != 2 || r.LinkedPassed != 2 {
		t.Fatalf("passes every linked case: %+v", r)
	}
}

// Other candidates, and fixes for other findings, keep PS1 for the cases
// linked to F1: they must not regress, and need not pass. F2 has its own
// linked case, which the fix passes; with none it fails closed (below).
func TestCasesLinkedToAnotherFindingKeepPS1(t *testing.T) {
	for _, finding := range []string{"", "F2"} {
		e := linkEnv(t)
		if err := e.p.AddSecurityCase(Case{ID: "loop2/F2", Class: ClassSkill, Input: []byte("skills/greet"), Expect: []byte("hello"), Finding: "F2"}); err != nil {
			t.Fatal(err)
		}
		r := e.propose(Candidate{Source: Local, Finding: finding, Files: Tree{"skills/greet": []byte("hello")}})
		if r.State != StateAdopted {
			t.Fatalf("finding %q: %+v", finding, r)
		}
	}
}

// A case linked to F that the evaluator cannot run on the fix counts as a
// fail, whatever the candidate's class: a fix cannot qualify by being
// untestable (6(f)).
func TestAnUnevaluatedLinkedCaseFailsTheFix(t *testing.T) {
	e := linkEnv(t)
	e.ev.decline = func(t Tree, _ Probe) bool { _, ok := t["config/x"]; return ok }
	r := e.propose(Candidate{Source: Local, Finding: "F1", Files: Tree{"config/x": []byte("1"), "skills/fix": []byte("yes"), "skills/fix2": []byte("yes")}})
	if r.State != StateRejected || r.Reason != ReasonLinked {
		t.Fatalf("%+v", r)
	}
}

// CHG-2: a candidate cannot add, remove or relink a case linked to its
// own finding. Cases are not tree files; every path that names the suite
// is rejected before evaluation, and the suite keeps its cases.
func TestACandidateCannotTouchItsFindingsCases(t *testing.T) {
	e := linkEnv(t)
	before := e.p.SecurityCount()
	for _, c := range []Candidate{
		{Source: Local, Finding: "F1", Files: Tree{"suites/held/F1/v1": []byte(`{"finding":"F2"}`)}},
		{Source: Local, Finding: "F1", Files: Tree{"suites/new": []byte(`{"finding":"F1"}`)}},
		{Source: Local, Finding: "F1", Files: Tree{"security/loop2/F1": []byte("x")}},
	} {
		if r := e.propose(c); r.State != StateRejected || !strings.Contains(r.Reason, "owner-approved intent") {
			t.Fatalf("%+v: %+v", c.Files, r)
		}
	}
	if n := e.p.SecurityCount(); n != before {
		t.Fatalf("security cases %d, were %d", n, before)
	}
	// The link is kept as added.
	for _, c := range e.p.st.Cases {
		if strings.HasSuffix(c.ID, "F1") || strings.HasPrefix(c.ID, "held/F1") {
			if c.Finding != "F1" {
				t.Fatalf("%s linked to %q", c.ID, c.Finding)
			}
		}
	}
}

// L3 on #464: a fix for a finding no case is linked to cannot pass every
// linked case vacuously; it is rejected, whatever else it passes.
func TestAFixForAFindingWithNoLinkedCaseIsRejected(t *testing.T) {
	e := linkEnv(t)
	r := e.propose(Candidate{Source: Local, Finding: "F9", Files: Tree{"skills/greet": []byte("hello")}})
	if r.State != StateRejected || r.Reason != ReasonUnlinked || r.Linked != 0 {
		t.Fatalf("%+v", r)
	}
}
