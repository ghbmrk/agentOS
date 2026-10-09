package owner

import "testing"

// REQ: CH-12, ADP-9

// SR3-3: a grant's terms are bound by the item's digest but never reach
// the text, which keeps its one line; an item without terms keeps the
// digest earlier builds saved (this one, from main before SR3-3), and
// terms never read as a detail.
func TestTermsAreBoundButNotTexted(t *testing.T) {
	it := Item{Object: "pre-allow invoice.send on mail, 50/day", Facts: Facts{Kind: GrantChange, Verb: "grant", NoRecipient: true}}
	plain := ItemSum(it)
	if plain != "1ebe71acb4892080e9704e9166cb34851e8dd829f436c158f61248d44613e709" {
		t.Fatalf("an item without terms changed its digest: %s", plain)
	}
	tm := it
	tm.Terms = NewTerms([]Term{{Label: "Amount", Value: "up to 150000.00"}})
	if tm.line() != it.line() {
		t.Fatalf("terms reached the text: %q", tm.line())
	}
	if ItemSum(tm) == plain {
		t.Fatal("terms are not part of the digest")
	}
	other := tm
	other.Terms = NewTerms([]Term{{Label: "Amount", Value: "up to 150000.01"}})
	split := tm
	split.Terms = NewTerms([]Term{{Label: "Amount", Value: "up"}, {Label: "to", Value: "150000.00"}})
	asDetail := it
	asDetail.Detail, asDetail.UndoBy = "Amount", "up to 150000.00"
	for _, x := range []Item{other, split, asDetail} {
		if ItemSum(x) == ItemSum(tm) {
			t.Fatalf("%+v digests as %+v", x, tm)
		}
	}
	// Items stay comparable, and the list round-trips; anything else
	// does not read as a list.
	if tm == other || tm != tm {
		t.Fatal("items compare wrongly")
	}
	if ts, ok := split.Terms.List(); !ok || len(ts) != 2 || ts[1].Value != "150000.00" {
		t.Fatalf("round trip: %+v %v", ts, ok)
	}
	for _, bad := range []TermList{"x", "[]", `[{"Label":"a","Value":"b","X":1}]`, `[{"Label":"a","Value":"b"}] []`} {
		if _, ok := bad.List(); ok {
			t.Fatalf("%q read as a list", bad)
		}
	}
}
