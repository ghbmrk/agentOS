package owner

import "testing"

// REQ: CH-4

// RFC 6238 Appendix B, SHA-1, cut to 6 digits (the last six of the 8-digit
// vectors). The seed is the RFC's published test value, not a real secret.
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	seed := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59: "287082", 1111111109: "081804", 1111111111: "050471",
		1234567890: "005924", 2000000000: "279037", 20000000000: "353130",
	} {
		if got := totpAt(seed, unix); got != want {
			t.Errorf("T=%d: got %s want %s", unix, got, want)
		}
	}
}

func TestGridHas100DistinctLabelsWithSixDigitCells(t *testing.T) {
	ls := GridLabels()
	if len(ls) != 100 || ls[0] != "A1" || ls[99] != "J10" {
		t.Fatalf("labels %d %s..%s", len(ls), ls[0], ls[len(ls)-1])
	}
	seed := []byte("synthetic-grid-seed")
	seen := map[string]bool{}
	for _, l := range ls {
		v := GridCell(seed, l)
		if len(v) != 6 || !allDigits(v) {
			t.Fatalf("%s=%q", l, v)
		}
		seen[v] = true
	}
	if len(seen) < 95 {
		t.Fatalf("only %d distinct cell values", len(seen))
	}
	if GridCell([]byte("other"), "A1") == GridCell(seed, "A1") {
		t.Fatal("cells do not depend on the seed")
	}
}
