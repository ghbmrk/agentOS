package owner

// REQ: CH-12

import "testing"

// CH-12: an item undone later by the owner's text (a learned change's
// UNDO) says so instead of "cannot be undone", and the restart digest
// tells it from the same item without.
func TestUndoableItemLine(t *testing.T) {
	it := Item{Object: "a learned skill, tested on 7 tasks", Facts: Facts{Kind: GrantChange, Verb: "adopt", NoRecipient: true}}
	if got := it.line(); got != "adopt a learned skill, tested on 7 tasks, cannot be undone" {
		t.Fatal(got)
	}
	u := it
	u.Undoable = true
	if got := u.line(); got != "adopt a learned skill, tested on 7 tasks, can be undone later" {
		t.Fatal(got)
	}
	if ItemSum(u) == ItemSum(it) {
		t.Fatal("Undoable is not part of the item digest")
	}
}
