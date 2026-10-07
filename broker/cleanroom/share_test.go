package cleanroom

import "testing"

// REQ: LOOP-2, LOOP-5
//
// W5c-ps2 (potency PS2): clean-room machines get a spare-meter Max share
// so their run loop cannot spend the whole budget.

func TestW5cPS2SpareShare(t *testing.T) {
	sh := SpareShare()
	if sh.Prefix != Prefix {
		t.Fatalf("prefix %q, want %q", sh.Prefix, Prefix)
	}
	if sh.Reserve != 0 {
		t.Fatalf("reserve %v, want 0 (Max-only share)", sh.Reserve)
	}
	if sh.Max != SpareShareMax || sh.Max <= 0 || sh.Max >= 1 {
		t.Fatalf("Max %v", sh.Max)
	}
	if Prefix != "cr-" {
		t.Fatalf("Prefix %q", Prefix)
	}
}
