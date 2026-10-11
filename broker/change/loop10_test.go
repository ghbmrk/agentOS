package change

import (
	"testing"
)

// REQ: LOOP-10, CHG-2

// P3-4b item 6: a fix candidate for an open finding fails qualification,
// each way with its own reason, and the security suite never shrinks.
func TestEachWeakeningFixFailsWithItsOwnReason(t *testing.T) {
	fixed := Tree{"skills/greet": []byte("hello"), "skills/fix": []byte("yes"), "skills/fix2": []byte("yes")}
	with := func(extra Tree) Tree {
		out := Tree{}
		for k, v := range fixed {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	cases := []struct {
		name string
		c    Candidate
		why  string
	}{
		{"(a) edits the regression", Candidate{Files: with(Tree{"suites/loop2/F1": []byte(`{"expect":"fail"}`)})},
			"changes suites, which only an owner-approved intent changes (CHG-2)"},
		{"(b) deletes it", Candidate{Files: fixed, Delete: []string{"suites/readme"}},
			"deletes from suites, which only an owner-approved intent changes (CHG-2)"},
		{"(c) skips it through graders", Candidate{Files: with(Tree{"graders/security": []byte(`"pass"`)})},
			"changes graders, which only an owner-approved intent changes (CHG-2)"},
		{"(c) skips it through config", Candidate{Files: with(Tree{"config/loop2.json": []byte(`{"fixtures_live":false}`)})},
			`sets "fixtures_live" in config/loop2.json, which turns fixture grading off or down; no candidate may (LOOP-10)`},
		{"(c) turns loop 2 off", Candidate{Files: with(Tree{"config/loops.json": []byte(`{"secure":false}`)})},
			`sets "secure" in config/loops.json, which turns loop 2 off or down; no candidate may (LOOP-10)`},
		{"(d) widens authority", Candidate{Files: with(Tree{"grants/p4": []byte(`{"verbs":["send"]}`)})},
			"changes grants, which no candidate may change (LOOP-10)"},
		{"(e) disables a check", Candidate{Files: with(Tree{"checks/hash": []byte(`"off"`)})},
			"changes checks, which no candidate may change (LOOP-10)"},
		{"(e) disables a check through config", Candidate{Files: with(Tree{"config/loop2.json": []byte(`{"checks":{"seeded":false}}`)})},
			`sets "checks" in config/loop2.json, which disables a loop 2 check; no candidate may (LOOP-10)`},
		{"(f) leaves the suite unevaluable", Candidate{Files: with(Tree{"config/x": []byte("1")})},
			"fails the security suite"},
		{"(g) fails a held-back case", Candidate{Files: Tree{"skills/greet": []byte("hello"), "skills/fix": []byte("yes")}},
			ReasonLinked},
	}
	seen := map[string]string{}
	for _, tc := range cases {
		e := linkEnv(t)
		// The evaluator cannot run the plain security probe on a tree
		// with config/x: coverage the fix would lose (6(f)).
		e.ev.decline = func(t Tree, pr Probe) bool {
			_, ok := t["config/x"]
			return ok && string(pr.Input) == exfilProbe
		}
		before := e.p.SecurityCount()
		tc.c.Source, tc.c.Finding = Local, "F1"
		r := e.propose(tc.c)
		if r.State != StateRejected || r.Reason != tc.why {
			t.Errorf("%s: %s %q", tc.name, r.State, r.Reason)
		}
		if n := e.p.SecurityCount(); n != before {
			t.Errorf("%s: security cases %d, were %d", tc.name, n, before)
		}
		if prev, dup := seen[r.Reason]; dup && tc.name[:3] != prev[:3] {
			t.Errorf("%s and %s share a reason", prev, tc.name)
		}
		seen[r.Reason] = tc.name
	}
	// The good fix qualifies.
	e := linkEnv(t)
	if r := e.propose(Candidate{Source: Local, Finding: "F1", Files: fixed}); r.State != StateAdopted {
		t.Fatalf("good fix: %+v", r)
	}
}

// Config keys outside the closed list stay ordinary config, and a
// loop-governing file left as it was is no change to it.
func TestOnlyListedConfigKeysGovernLoops(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.Initial["config/loop2.json"] = []byte(`{"checks":{"seeded":true},"note":"a"}`)
	})
	e.cases(12, ClassSkill, "skills/greet", "hello")
	e.owner.approve = true // config is a behavior change the owner approves (CHG-3)
	r := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), "config/loop2.json": []byte(`{"note":"b","checks":{"seeded":true}}`)}})
	if r.State == StateRejected {
		t.Fatalf("unlisted key: %+v", r)
	}
	for _, after := range [][]byte{[]byte(`not json`), nil} {
		c := Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}}
		if after == nil {
			c.Delete = []string{"config/loop2.json"}
		} else {
			c.Files["config/loop2.json"] = after
		}
		if r := e.propose(c); r.State != StateRejected || r.Reason != "changes config/loop2.json, which governs the loops; no candidate may (LOOP-10)" {
			t.Fatalf("%q: %+v", after, r)
		}
	}
}
