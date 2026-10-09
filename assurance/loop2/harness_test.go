package main

// Unit tests for the harness's own checks (P3-4b-2b). Run them through
// `run.py --go-test`, which overlays this directory into the broker module
// and points A11_CATALOG at the committed catalog.

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/loops"
)

func rule(t *testing.T, s string) change.TreeRule {
	t.Helper()
	r, err := parseRule([]byte(s))
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return r
}

func record1(id, fix string) loops.Record {
	return loops.Record{Finding: loops.Finding{ID: id}, Fix: fix}
}

// The evidence check (L3 on #490, point 1): exactly one record for the
// finding, and it records the fix as adopted.
func TestEvidenceNeedsOneAdoptedRecord(t *testing.T) {
	adopted := string(change.StateAdopted)
	for _, tc := range []struct {
		name string
		recs []loops.Record
		ok   bool
	}{
		{"no record at all", nil, false},
		{"only another finding's record", []loops.Record{record1("other", adopted)}, false},
		{"fix not adopted", []loops.Record{record1("f1", string(change.StateRejected))}, false},
		{"fix empty", []loops.Record{record1("f1", "")}, false},
		{"two records", []loops.Record{record1("f1", adopted), record1("f1", adopted)}, false},
		{"one adopted record", []loops.Record{record1("other", ""), record1("f1", adopted)}, true},
	} {
		got := evidenceFailure(tc.recs, "f1")
		if (got == "") != tc.ok {
			t.Errorf("%s: evidenceFailure = %q, want ok=%v", tc.name, got, tc.ok)
		}
	}
}

// Security 1 on #490: a held clause leaked as raw bytes, in a layout that
// is not canonical, is caught even when each of its fields appears in the
// visible test.
func TestAuditCatchesRawHeldClauseWithSharedFields(t *testing.T) {
	visible := rule(t, `{"tree_rule": [
		{"path": "config/a.json", "pointer": "/x", "op": "le", "value": 1},
		{"path": "config/a.json", "pointer": "/y", "op": "le", "value": 2}]}`)
	raw := []byte(`{"tree_rule": [ { "op": "le",  "value": 2,
		"pointer": "/x", "path": "config/a.json" } ]}`)
	held := map[string][]byte{"v1": raw}
	vis := visible.Encode()

	rec := append(append([]byte{}, vis...), 0)
	if r := audit(rec, 1, 1, visible, held); !r.Clean {
		t.Fatalf("the visible test alone is not clean: %v", r.Hits)
	}
	leaky := append(append(append([]byte{}, rec...), "detail "...), raw...)
	r := audit(leaky, 1, 1, visible, held)
	if r.Clean {
		t.Fatal("a raw held clause whose fields the visible test shares passed the audit")
	}
	if len(r.Hits) != 1 || !strings.Contains(r.Hits[0], "whole clause") {
		t.Errorf("hits = %v, want one whole-clause hit", r.Hits)
	}
	// The canonical form, as before, is caught too.
	canonical := append(append([]byte{}, rec...), clauseForms(rule(t, string(raw)).Clauses[0])[0]...)
	if r := audit(canonical, 1, 1, visible, held); r.Clean {
		t.Error("the canonical held clause passed the audit")
	}
}

// A held clause the visible test does not wholly share must have a field
// the test lacks, so the field-level audit always has something to match.
func TestFieldlessHeldClauses(t *testing.T) {
	visible := rule(t, `{"tree_rule": [
		{"path": "config/a.json", "pointer": "/x", "op": "le", "value": 1},
		{"path": "config/a.json", "pointer": "/y", "op": "le", "value": 2}]}`)
	for _, tc := range []struct {
		held string
		bad  bool
	}{
		{`{"tree_rule": [{"path": "config/a.json", "pointer": "/x", "op": "le", "value": 2}]}`, true},
		{`{"tree_rule": [{"path": "config/a.json", "pointer": "/y", "op": "absent"}]}`, true},
		{`{"tree_rule": [{"path": "config/a.json", "pointer": "/x", "op": "le", "value": 1}]}`, false},
		{`{"tree_rule": [{"path": "config/a.json", "pointer": "/x", "op": "le", "value": 3}]}`, false},
		{`{"tree_rule": [{"path": "config/b.json", "pointer": "/x", "op": "le", "value": 2}]}`, false},
	} {
		got := fieldless(visible, rule(t, tc.held))
		if (len(got) > 0) != tc.bad {
			t.Errorf("%s: fieldless = %v, want bad=%v", tc.held, got, tc.bad)
		}
	}
}

func catalogForTest(t *testing.T) *catalog {
	t.Helper()
	root := os.Getenv("A11_CATALOG")
	if root == "" {
		t.Fatal("A11_CATALOG is not set; run through run.py --go-test")
	}
	c, err := loadCatalog(root)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Every committed seed passes the new rule, and a seed whose held clause
// shares every field with its visible test is refused and runs red.
func TestValidateRefusesAFieldlessHeldClause(t *testing.T) {
	c := catalogForTest(t)
	for _, s := range c.Seeds {
		if bad := c.validate(s); len(bad) > 0 {
			t.Errorf("%s: %v", s.ID, bad)
		}
	}
	s := *c.Seeds[0]
	test := rule(t, string(s.Test))
	a, b := test.Clauses[0], test.Clauses[len(test.Clauses)-1]
	mixed := change.Clause{Path: a.Path, Pointer: b.Pointer, Op: a.Op, Value: a.Value}
	if a.Op == change.OpAbsent || len(a.Value) == 0 {
		mixed.Op, mixed.Value = b.Op, b.Value
	}
	enc, _ := json.Marshal(map[string]any{"tree_rule": []change.Clause{mixed}})
	s.Held = map[string][]byte{"v1": enc}
	found := false
	for _, f := range c.validate(&s) {
		found = found || strings.Contains(f, "no field the visible test lacks")
	}
	if !found {
		t.Errorf("%s: validate did not refuse held clause %s: %v", s.ID, enc, c.validate(&s))
	}
	if run := c.run(context.Background(), &s, false); run.Pass {
		t.Errorf("%s: the run passed with a fieldless held clause", s.ID)
	}
}

// The leaking-adapter control runs on every valid seed, not only the first.
func TestLeakingAdapterControlOnEverySeed(t *testing.T) {
	c := catalogForTest(t)
	seen := map[string]bool{}
	for _, ct := range controls(context.Background(), c) {
		if ct.Name == "leaking-adapter" {
			if !ct.Caught {
				t.Errorf("leaking-adapter on %s was not caught: %s", ct.SeedID, ct.Detail)
			}
			seen[ct.SeedID] = true
		}
	}
	for _, s := range c.Seeds {
		if !seen[s.ID] {
			t.Errorf("leaking-adapter did not run on %s", s.ID)
		}
	}
}
