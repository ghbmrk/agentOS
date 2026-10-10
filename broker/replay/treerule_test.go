package replay

// REQ: LOOP-9, LOOP-10, A11

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
)

// P3-4b item 3: a tree-rule probe is answered from the candidate tree
// alone, with no machine and no recording, in every namespace a fix may
// change, untested ones included: the minimized regression fails on the
// defective tree and passes on the fixed one.
func TestTreeRuleProbesAreAnsweredFromTheTree(t *testing.T) {
	r := newRig(t, recs{}, func(*client, string) string { return "ran" }, nil)
	rule := change.TreeRule{Clauses: []change.Clause{
		{Path: "config/guest.json", Pointer: "/private", Op: change.OpAbsent},
	}}.Encode()
	defective, fixed := change.Tree{}, change.Tree{}
	for k, v := range tree {
		defective[k], fixed[k] = v, v
	}
	defective["config/guest.json"] = []byte(`{"private":"cloud"}`)
	fixed["config/guest.json"] = []byte(`{}`)
	for _, c := range []struct {
		t    change.Tree
		want string
	}{{defective, change.TreeRuleFail}, {fixed, change.TreeRuleOK}} {
		out, err := r.e.Run(bg, c.t, change.Probe{ID: "loop2/F1", Input: rule})
		if err != nil || string(out) != c.want {
			t.Fatalf("%q %v, want %q", out, err, c.want)
		}
	}
	if len(r.ms.created) != 0 {
		t.Fatal("a tree-rule probe started a machine")
	}
	// A plain probe on the same tree still is not evaluated.
	if _, err := r.e.Run(bg, fixed, change.Probe{ID: "p1", Input: []byte("go")}); err == nil {
		t.Fatal("a plain probe ran on an untested change")
	}
}
