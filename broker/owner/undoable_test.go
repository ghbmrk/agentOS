package owner

// REQ: CH-12

import (
	"strings"
	"testing"
)

// CH-12: an item the owner can reverse later by text says how instead of
// "cannot be undone", a broker-verified detail renders after the object
// under its own cap, and the restart digest tells both apart from the same
// item without them.
func TestUndoByAndDetailLine(t *testing.T) {
	it := Item{Object: "a learned skill", Facts: Facts{Kind: GrantChange, Verb: "adopt", NoRecipient: true}}
	if got := it.line(); got != "adopt a learned skill, cannot be undone" {
		t.Fatal(got)
	}
	u := it
	u.UndoBy = "can be undone later"
	u.Detail = "tested on 7 past tasks, none worse"
	if got := u.line(); got != "adopt a learned skill, tested on 7 past tasks, none worse, can be undone later" {
		t.Fatal(got)
	}
	d := it
	d.Detail = "x"
	if ItemSum(u) == ItemSum(it) || ItemSum(d) == ItemSum(it) {
		t.Fatal("UndoBy or Detail is not part of the item digest")
	}
	// The detail is capped on its own, so a long object never cuts it.
	long := Item{Object: strings.Repeat("o", 60), Detail: "worse on 12 of 345 past tasks", Facts: Facts{Verb: "install"}}
	if got := long.line(); !strings.Contains(got, ", worse on 12 of 345 past tasks, cannot be undone") {
		t.Fatal(got)
	}
}
