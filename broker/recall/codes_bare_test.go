package recall

// REQ: CRED-1-B1, CRED-1-B2

import (
	"math/rand"
	"testing"
)

// A bare two-group code whose letters lie in a hex or base32 alphabet is
// removed even when one group holds no digit (RECALL-bare-codes, #2232).
// Synthetic codes only.
func TestBareHexTwoGroupCodesAreScrubbed(t *testing.T) {
	sc := NewScrubber(nil)
	for _, v := range []string{
		"abcde-12345", "fedcb-a0918", "eaddb-7c3f1", // hex, letters-only first group
		"12345-abcde", "90817-fcedb", // hex, letters-only last group
		"ABCDE-12345", "9F3C1-BEADF", // upper-case hex
		"QWERT-23456", "MZXWY-6K3PQ", "ZXWVQ-75432", // base32 (A-Z, 2-7)
		"abcdef-123456", // hex, 6-6
	} {
		if out := sc.Scrub(v); out != Removed {
			t.Errorf("alone: %q -> %q", v, out)
		}
		if out, want := sc.Scrub("codes: "+v+" keep safe"), "codes: "+Removed+" keep safe"; out != want {
			t.Errorf("in text: %q -> %q", v, out)
		}
	}
}

// Hyphenated words, product numbers and postal numbers are kept.
func TestHyphenatedWordsAndNumbersAreKept(t *testing.T) {
	sc := NewScrubber(nil)
	for _, in := range []string{
		// hyphenated words: letters only
		"linux-amd64", "linux-arm64", "zxwvq-75432", // lower-case: base32 is read in capitals only
		"build-tools", "check-point", "cross-field", "state-owned", "short-lived", "write-ahead", "added-value",
		// product and model numbers
		"MODEL-10019", "SERIES-900100", "Model-23456", "Suite-23456", "Route-80801", "trace-10019", "Apple-19098",
		// postal numbers: digits only
		"12345-6789", "02139-4307", "90210-1234", "10115-80331",
		// pins: title case (oneCase), uneven groups, digits 8 and 9 outside base32
		"Faced-12345", "Decaf-12345", "ABCDE-2345", "QWERT-23489",
	} {
		if out := sc.Scrub(in); out != in {
			t.Errorf("%q -> %q", in, out)
		}
	}
}

// A seeded sample of 20,000 synthetic GitHub-style hex codes (xxxxx-xxxxx)
// that mix letters and digits: none is kept. All-digit codes (about 0.9% of
// hex codes) are not covered (R12) and are not drawn.
func TestBareCodeLeakRateIsZeroOnSampledHexCodes(t *testing.T) {
	sc := NewScrubber(nil)
	r := rand.New(rand.NewSource(2232))
	const hex = "0123456789abcdef"
	group := func() string {
		b := make([]byte, 5)
		for i := range b {
			b[i] = hex[r.Intn(len(hex))]
		}
		return string(b)
	}
	kept := 0
	for n := 0; n < 20000; {
		v := group() + "-" + group()
		if !hasDigit(v) || !hasLetter(v) {
			continue
		}
		n++
		if sc.Scrub(v) != Removed {
			if kept < 5 {
				t.Errorf("kept %q", v)
			}
			kept++
		}
	}
	if kept > 0 {
		t.Errorf("%d of 20000 kept", kept)
	}
}
