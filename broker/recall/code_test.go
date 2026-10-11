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
		checkCodeInText(t, sc, v)
	}
	// Seed 17034256731814298294: a group ("tial") that is a substring of the
	// Removed marker, which a substring check took for a leak.
	checkCodeInText(t, sc, "qrio-tial-pubt-wtqm-wjxk-exax-sbuk")
}

// checkCodeInText requires the whole code, and only the code, to be replaced
// in text. An exact match, because a short group can be a substring of the
// Removed marker or of the surrounding words.
func checkCodeInText(t *testing.T, sc *Scrubber, v string) {
	t.Helper()
	if out, want := sc.Scrub("codes ("+v+"), keep safe"), "codes ("+Removed+"), keep safe"; out != want {
		t.Fatalf("in text: %q -> %q", v, out)
	}
}

// Hyphenated words and dates, whose parts differ in length, are not codes.
func TestHyphenatedTextKept(t *testing.T) {
	sc := NewScrubber(nil)
	for _, in := range []string{"a well-known-thing", "state-of-the-art", "2026-10-07", "INV-2026-0042", "follow-up", "Jean-Pierre-Rampal", "blue-fish-tanks",
		"rapid-fire-test", "stop-start-stop", "data-sets-ready"} {
		if out := sc.Scrub(in); out != in {
			t.Fatalf("over-scrubbed: %q -> %q", in, out)
		}
	}
}

// The even-group rule trades recall for custody (R4, R10): a dash-written
// number cut into three or more even groups of 4 to 8 is removed like a
// numeric backup code, while numbers with uneven groups are kept. Moving a
// line between these lists is a deliberate change to that trade.
func TestGroupedNumbersTradeoff(t *testing.T) {
	sc := NewScrubber(nil)
	for _, in := range []string{
		"Order 1234-5678-9012 shipped",      // order number, 4-4-4
		"Call 0412-3456-7890 tomorrow",      // phone, 4-4-4
		"tracking 9400-1118-9922-3344-5566", // parcel tracking, digits only
		"ISBN 9783-1614-8410",               // ISBN-13 cut 4-4-4
		"card 4111-1111-1111-1111",          // card number
	} {
		if out := sc.Scrub(in); !strings.Contains(out, Removed) {
			t.Errorf("expected removal: %q -> %q", in, out)
		}
	}
	for _, in := range []string{
		"Call 555-123-4567",     // US phone, 3-3-4
		"Call +1-555-0142-7788", // 1-3-4-4
		"Call 0800-123-456",     // 4-3-3
		"Ticket TKT-2026-0042",  // 3-4-4
		"Booking BK-7731-9902",  // two digit groups
		"Due 2026-10-07",        // date
	} {
		if out := sc.Scrub(in); out != in {
			t.Errorf("expected kept: %q -> %q", in, out)
		}
	}
}
