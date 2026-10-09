package change

import (
	"errors"
	"testing"
)

// REQ: LOOP-9, LOOP-10, A11

// P3-4b tree-rule semantics: a conjunction of clauses over tree files,
// each a JSON Pointer target checked with one of four ops. Evaluation
// reads only the tree and is deterministic (ARC-2).
func TestTreeRuleSemantics(t *testing.T) {
	tree := Tree{
		"routing/rule.json":  []byte(`{"private":{"routes":["local","cloud"],"max":3},"name":"r"}`),
		"config/notes.json":  []byte(`not json`),
		"context/mail.json":  []byte(`{"select":["mail"]}`),
		"skills/greet":       []byte(`"hi"`),
		"procedures/a~b.txt": []byte(`{}`),
	}
	cases := []struct {
		name string
		c    Clause
		want bool
	}{
		{"eq holds", Clause{Path: "routing/rule.json", Pointer: "/name", Op: "eq", Value: []byte(`"r"`)}, true},
		{"eq canonical", Clause{Path: "routing/rule.json", Pointer: "/private", Op: "eq", Value: []byte(`{"max":3, "routes":["local","cloud"]}`)}, true},
		{"eq differs", Clause{Path: "routing/rule.json", Pointer: "/name", Op: "eq", Value: []byte(`"s"`)}, false},
		{"eq whole doc", Clause{Path: "skills/greet", Op: "eq", Value: []byte(`"hi"`)}, true},
		{"subset holds", Clause{Path: "routing/rule.json", Pointer: "/private/routes", Op: "subset", Value: []byte(`["local","cloud","x"]`)}, true},
		{"subset fails", Clause{Path: "routing/rule.json", Pointer: "/private/routes", Op: "subset", Value: []byte(`["local"]`)}, false},
		{"subset type mismatch", Clause{Path: "routing/rule.json", Pointer: "/name", Op: "subset", Value: []byte(`["r"]`)}, false},
		{"le holds", Clause{Path: "routing/rule.json", Pointer: "/private/max", Op: "le", Value: []byte(`3`)}, true},
		{"le exact", Clause{Path: "routing/rule.json", Pointer: "/private/max", Op: "le", Value: []byte(`2.99999999999999999999`)}, false},
		{"le type mismatch", Clause{Path: "routing/rule.json", Pointer: "/name", Op: "le", Value: []byte(`3`)}, false},
		{"missing target fails", Clause{Path: "routing/rule.json", Pointer: "/public", Op: "eq", Value: []byte(`1`)}, false},
		{"missing file fails", Clause{Path: "routing/none.json", Op: "eq", Value: []byte(`1`)}, false},
		{"absent target", Clause{Path: "routing/rule.json", Pointer: "/public", Op: "absent"}, true},
		{"absent present", Clause{Path: "routing/rule.json", Pointer: "/name", Op: "absent"}, false},
		{"absent file", Clause{Path: "routing/none.json", Op: "absent"}, true},
		{"absent file, pointer", Clause{Path: "routing/none.json", Pointer: "/a", Op: "absent"}, true},
		{"not json fails", Clause{Path: "config/notes.json", Op: "eq", Value: []byte(`"not json"`)}, false},
		{"not json, absent pointer fails", Clause{Path: "config/notes.json", Pointer: "/a", Op: "absent"}, false},
		{"not json, absent whole doc", Clause{Path: "config/notes.json", Op: "absent"}, false},
		{"array index", Clause{Path: "routing/rule.json", Pointer: "/private/routes/1", Op: "eq", Value: []byte(`"cloud"`)}, true},
		{"array index past end", Clause{Path: "routing/rule.json", Pointer: "/private/routes/2", Op: "absent"}, true},
		{"escaped pointer", Clause{Path: "context/mail.json", Pointer: "/select/0", Op: "eq", Value: []byte(`"mail"`)}, true},
	}
	for _, c := range cases {
		r := TreeRule{Clauses: []Clause{c.c}}
		if err := r.Valid(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := r.Holds(tree); got != c.want {
			t.Errorf("%s: holds = %v, want %v", c.name, got, c.want)
		}
	}
	// Conjunction; the empty set passes.
	if !(TreeRule{}).Holds(tree) {
		t.Error("the empty clause set fails")
	}
	both := TreeRule{Clauses: []Clause{cases[0].c, cases[2].c}}
	if both.Holds(tree) {
		t.Error("a conjunction with a failing clause holds")
	}
	// Pointer escapes (RFC 6901): ~1 is "/", ~0 is "~".
	esc := Tree{"config/a.json": []byte(`{"a/b":{"c~d":1}}`)}
	if !(TreeRule{Clauses: []Clause{{Path: "config/a.json", Pointer: "/a~1b/c~0d", Op: "eq", Value: []byte(`1`)}}}).Holds(esc) {
		t.Error("escaped pointer not resolved")
	}
}

// An unknown op, a bad path or pointer, or a missing value makes the
// whole test invalid: it is rejected when added, never counted as passing.
func TestAnInvalidTreeRuleIsRejectedWhenAdded(t *testing.T) {
	bad := []Clause{
		{Path: "routing/rule.json", Op: "ne", Value: []byte(`1`)},
		{Path: "../etc/passwd", Op: "absent"},
		{Path: "routing/rule.json", Pointer: "name", Op: "absent"},
		{Path: "routing/rule.json", Op: "eq"},
		{Path: "routing/rule.json", Op: "absent", Value: []byte(`1`)},
	}
	// A value that is not JSON cannot even be encoded into a case.
	if err := (TreeRule{Clauses: []Clause{{Path: "routing/rule.json", Op: "le", Value: []byte(`{`)}}}).Valid(); !errors.Is(err, ErrInvalidTreeRule) {
		t.Errorf("bad value: %v", err)
	}
	e := newEnv(t, nil)
	for i, c := range bad {
		in := TreeRule{Clauses: []Clause{{Path: "skills/greet", Op: "absent"}, c}}.Encode()
		err := e.p.AddSecurityCase(Case{ID: "loop2/bad" + string(rune('a'+i)), Input: in, Expect: []byte(TreeRuleOK)})
		if !errors.Is(err, ErrInvalidTreeRule) {
			t.Errorf("clause %d: %v", i, err)
		}
	}
	// A rule with keys besides the clause list is invalid too.
	if err := e.p.AddSecurityCase(Case{ID: "loop2/extra", Input: []byte(`{"tree_rule":[],"skip":true}`), Expect: []byte(TreeRuleOK)}); !errors.Is(err, ErrInvalidTreeRule) {
		t.Errorf("extra key: %v", err)
	}
	if _, ok, _ := ParseTreeRule([]byte(exfilProbe)); ok {
		t.Error("a plain probe read as a tree rule")
	}
}

// The answering hook: a tree-rule probe is answered from the tree alone,
// "ok" when it holds.
func TestAnswerTreeRule(t *testing.T) {
	r := TreeRule{Clauses: []Clause{{Path: "skills/greet", Op: "eq", Value: []byte(`"hi"`)}}}.Encode()
	out, ok := AnswerTreeRule(Tree{"skills/greet": []byte(`"hi"`)}, r)
	if !ok || string(out) != TreeRuleOK {
		t.Fatalf("%q %v", out, ok)
	}
	out, ok = AnswerTreeRule(Tree{"skills/greet": []byte(`"no"`)}, r)
	if !ok || string(out) == TreeRuleOK {
		t.Fatalf("%q %v", out, ok)
	}
	if _, ok := AnswerTreeRule(Tree{}, []byte("probe:x")); ok {
		t.Fatal("answered a probe that is no tree rule")
	}
}

// Minimize reduces a failing rule to a 1-minimal clause set: it still
// fails, and dropping any remaining clause makes it pass.
func TestMinimizeIsOneMinimal(t *testing.T) {
	tree := Tree{"routing/rule.json": []byte(`{"private":["local","cloud"],"n":1}`), "skills/greet": []byte(`"hi"`)}
	r := TreeRule{Clauses: []Clause{
		{Path: "skills/greet", Op: "eq", Value: []byte(`"hi"`)}, // padding
		{Path: "routing/rule.json", Pointer: "/private", Op: "subset", Value: []byte(`["local"]`)},
		{Path: "routing/rule.json", Pointer: "/n", Op: "le", Value: []byte(`5`)}, // padding
	}}
	m := r.Minimize(tree)
	if m.Holds(tree) || len(m.Clauses) != 1 || m.Clauses[0].Op != "subset" {
		t.Fatalf("%+v", m)
	}
	for i := range m.Clauses {
		less := TreeRule{Clauses: append(append([]Clause{}, m.Clauses[:i]...), m.Clauses[i+1:]...)}
		if !less.Holds(tree) {
			t.Fatalf("not 1-minimal: dropping %d still fails", i)
		}
	}
	// A rule that holds is returned as it is.
	if ok := (TreeRule{Clauses: r.Clauses[:1]}); len(ok.Minimize(tree).Clauses) != 1 {
		t.Fatal("a holding rule was changed")
	}
}
