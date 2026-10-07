package change

import "testing"

// REQ: LOOP-10
// FixturesLive gate (Security L3 on W5a / #169): only AddSecurityCase may
// create a loop2/ security fixture; a Guard-generated fixture is trusted.
// Candidates cannot write loop2/, security/, or suites/ paths (C24).
func TestW5aFxGateOnlyAddSecurityCaseCreatesLoop2(t *testing.T) {
	e := newEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	c := Case{ID: Loop2Fixture + "gate", Class: ClassSkill, Input: []byte("skills/x"), Expect: []byte("no")}
	if err := e.p.AddSecurityCase(c); err != nil {
		t.Fatal(err)
	}
	got, ok := e.p.st.Cases[c.ID]
	if !ok || !got.Security {
		t.Fatalf("AddSecurityCase did not store a security loop2 case: %+v ok=%v", got, ok)
	}
	for _, path := range []string{"loop2/evil", "security/loop2/evil", "suites/loop2/evil"} {
		r := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), path: []byte("x")}})
		if r.State != StateRejected {
			t.Fatalf("%s: %+v", path, r)
		}
	}
}
