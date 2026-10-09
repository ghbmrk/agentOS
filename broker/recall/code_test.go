package recall

// REQ: CRED-1

import (
	"path/filepath"
	"strings"
	"testing"
)

// leakedCode is the recovery code TestCredentialsNeverStored stored on #617's
// CI, recaptured locally: base32 letters only (no digit) and with enough
// repeats that its entropy (3.48) is under the scrubber's digit-free floor.
// Synthetic; minted by the canary generator.
const leakedCode = "JMNOX-CPMGJ-JYTLJ-OOYJG-PXOYY-JDNTG"

// A recovery code carried as a fact object has no "recovery code:" key beside
// it, so its shape alone must remove it, on disk and in what Get returns.
func TestDigitFreeRecoveryCodeNotStored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recall")
	st, err := OpenDir(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ix := open(t, st)
	cs := []canary{{"recovery_code", leakedCode, strings.ReplaceAll(leakedCode, "-", "")}}
	id := mustIngest(t, ix, Item{Source: Source{Kind: "mail", Ref: "<rc@x>"},
		Text:  "Keep these somewhere safe: " + leakedCode,
		Facts: []Fact{{"account", "recovery", leakedCode}}})
	if hits := leaked(cs, string(readDir(t, path))); len(hits) > 0 {
		t.Fatalf("stored: %v", hits)
	}
	it, _ := ix.Get(id)
	if hits := leaked(cs, it.Text+" "+it.Facts[0].Object); len(hits) > 0 {
		t.Fatalf("returned: %q %+v", it.Text, it.Facts)
	}
}

// Property: any grouped code (three or more dash-separated groups of one
// length, 4 to 8 characters) is removed, whatever its alphabet or entropy:
// letters only, digits only, one case, or a few repeated symbols.
func TestGroupedCodesRemoved(t *testing.T) {
	r := canaryRand(t)
	alphabets := []string{b32, b32[:26], strings.ToLower(b32[:26]), "0123456789", "ABCDEFGH", "JMNOXY", "ab12"}
	sc := NewScrubber(nil)
	for i := 0; i < 20000; i++ {
		a := alphabets[r.IntN(len(alphabets))]
		n, size := 3+r.IntN(6), 4+r.IntN(5)
		groups := make([]string, n)
		for g := range groups {
			groups[g] = pick(r, a, size)
		}
		v := strings.Join(groups, "-")
		if out := sc.Scrub(v); out != Removed {
			t.Fatalf("alone: %q -> %q", v, out)
		}
		if out := sc.Scrub("codes (" + v + "), keep safe"); strings.Contains(out, groups[1]) {
			t.Fatalf("in text: %q -> %q", v, out)
		}
	}
}

// Hyphenated words and dates, whose parts differ in length, are not codes.
func TestHyphenatedTextKept(t *testing.T) {
	sc := NewScrubber(nil)
	for _, in := range []string{"a well-known-thing", "state-of-the-art", "2026-10-07", "INV-2026-0042", "follow-up", "Jean-Pierre-Rampal", "blue-fish-tanks"} {
		if out := sc.Scrub(in); out != in {
			t.Fatalf("over-scrubbed: %q -> %q", in, out)
		}
	}
}
