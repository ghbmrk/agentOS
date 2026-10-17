package recall

// REQ: CRED-1

import (
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic codes (RECALL-canary-3); never real values.

// A recovery or backup code list after its key loses every code, whatever
// separates them, while prose with no key keeps its words (no bare space rule:
// "have been with them" is 4-4-4-4).
func TestKeyedCodeListsRemoved(t *testing.T) {
	sc := NewScrubber(nil)
	for _, c := range []struct{ in, want string }{
		{"Your recovery code: A7KQ2 M3XZP 9RTB4 WQ8LN", "Your recovery code: " + Removed},
		{"Backup codes:\n1234 5678\n8765 4321", "Backup codes:\n" + Removed},
		{"Your recovery code: A7KQ2 M3XZP 9RTB4 WQ8LN. Keep it safe.", "Your recovery code: " + Removed + ". Keep it safe."},
		{"Backup code(s): abcd efgh ijkl mnop", "Backup code(s): " + Removed},
		{"Your backup codes are:\n1. 4821 9930\n2. 1177 0045\nKeep them safe.", "Your backup codes are:\n" + Removed + "\nKeep them safe."},
		{"recovery codes:\n- a7kq2-m3xzp\n- 9rtb4-wq8ln\n\nThanks", "recovery codes:\n" + Removed + "\n\nThanks"},
		{"Backup codes\n4821, 9930, 1177; 0045\nDone", "Backup codes\n" + Removed + "\nDone"},
		{"recovery code is 4821 9930 1177", "recovery code is " + Removed},
		{"recovery codes A7KQ2 M3XZP were printed", "recovery codes " + Removed + " were printed"},
		{"recovery codes are ABCD EFGH IJKL", "recovery codes are " + Removed},
	} {
		if out := sc.Scrub(c.in); out != c.want {
			t.Errorf("%q\n got %q\nwant %q", c.in, out, c.want)
		}
	}
	for _, in := range []string{
		"have been with them",
		"They have been with them since 2019.",
		"Recovery codes were sent to your phone.",
		"backup codes for 2025 are ready",
		"Your recovery codes have been with them",
		"Print your backup codes and keep them safe",
	} {
		if out := sc.Scrub(in); out != in {
			t.Errorf("over-scrubbed: %q -> %q", in, out)
		}
	}
}

// Codes cut by a separator other than ASCII '-' are removed: '.', '_' and the
// Unicode dashes alone; spaces of any kind after a key.
func TestCodeSeparatorsRemoved(t *testing.T) {
	sc := NewScrubber(nil)
	groups := []string{"A7KQ2", "M3XZP", "9RTB4", "WQ8LN"}
	for _, sep := range []string{".", "_", "‑", "–", "−", "‐", "—", "－", "﹣"} {
		v := strings.Join(groups, sep)
		if out := sc.Scrub(v); out != Removed {
			t.Errorf("alone %q: %q", sep, out)
		}
		if out, want := sc.Scrub("codes ("+v+"), keep safe"), "codes ("+Removed+"), keep safe"; out != want {
			t.Errorf("in text %q: %q", sep, out)
		}
	}
	for _, sep := range []string{" ", " ", " ", " ", "　", "  "} {
		v := strings.Join(groups, sep)
		if out, want := sc.Scrub("recovery code: "+v), "recovery code: "+Removed; out != want {
			t.Errorf("keyed %q: %q", sep, out)
		}
	}
}

// Group shapes beyond 3+ even groups of 4 to 8: two groups (GitHub's
// xxxxx-xxxxx), groups of 3 and of 9 or more, and an uneven last group.
func TestCodeShapesRemoved(t *testing.T) {
	sc := NewScrubber(nil)
	for _, v := range []string{
		"a1b2c-3d4e5", "9f3c1-b77e0", "0a1b2-34567", // GitHub, 5-5 hex
		"A7K-Q2M-3XZ-P9R",                        // 3-3-3-3 mixed
		"482-993-117-004",                        // 3-3-3-3 digits
		"A7K-Q2M-3XZ",                            // every group mixed
		"A7KQ2M3XZ-P9RTB4WQ8-LN3K5J7HX",          // 9-9-9
		"QWERTYUIOPAS-DFGHJKLZXCVB-NMQWERTYUIOP", // 12-12-12 letters
		"A7KQ2-M3XZP-9RTB4-WQ8",                  // uneven last group
		"48219-93011-77004-5",                    // digits, uneven last
		"A7KQ2.M3XZP.9RTB",                       // '.' uneven last
		"a7kq2_m3xzp_9rtb4_wq8ln",                // '_'
		"jmnox.cpmgj.jytlj.ooyjg",                // '.', letters, 20
		"JMNOX_CPMGJ_JYTLJ_OOYJG",                // '_', letters, 20
	} {
		if out := sc.Scrub(v); out != Removed {
			t.Errorf("alone: %q -> %q", v, out)
		}
		if out, want := sc.Scrub("codes ("+v+"), keep safe"), "codes ("+Removed+"), keep safe"; out != want {
			t.Errorf("in text: %q -> %q", v, out)
		}
	}
	// A code after a prefix it does not belong to loses only the code.
	if out, want := sc.Scrub("ref-A7KQ2-M3XZP-9RTB4"), "ref-"+Removed; out != want {
		t.Errorf("prefixed: %q", out)
	}
}

// Dates, phone numbers, addresses, versions, identifiers and prose that the
// wider shapes could reach are kept.
func TestCodeGuardsKept(t *testing.T) {
	sc := NewScrubber(nil)
	for _, in := range []string{
		"2026-10-07", "2026.10.07", "07.10.2026", "2026_10_07", "2026–10–07",
		"555-123-4567", "555.123.4567", "+1-800-555-0199", "020-7946-0958", "Call 0800-123-456",
		"192.168.100.200", "10.0.0.1", "fe80::1", "v1.2.3", "v2.10.4", "go1.26.8", "3.14159", "1.000.000", "100.000.000",
		"mail.example.com", "www.example.co.uk", "read_file_data", "MAX_SIZE_1024", "user_id_1234", "ISO_8859_1",
		"PROJ-1234", "ABC-123", "INV-2026-0042", "TKT-2026-0042", "COVID-19", "2024-2025", "1000-2000", "salary 50000-60000",
		"one-for-all", "pay-per-use", "well-done", "self-help", "linux-amd64", "model-X1234",
		"a well-known-thing", "state-of-the-art", "Jean-Pierre-Rampal", "data-sets-ready", "follow-up",
		"pages 10–12", "1990–2000", "a well‑known thing", "ZIP 12345-6789",
	} {
		if out := sc.Scrub(in); out != in {
			t.Errorf("over-scrubbed: %q -> %q", in, out)
		}
	}
}

// Confusable letters, fullwidth forms, mathematical alphanumerics and
// zero-width characters do not hide a code.
func TestConfusableCodesRemoved(t *testing.T) {
	sc := NewScrubber(nil)
	for _, v := range []string{
		"А7КQ2-М3XZР-9RTB4-WQ8LN",             // Cyrillic A, K, M, P
		"ΑΒΕΖΗ-ΚΜΝΟΡ-TXYZA",                   // Greek, digit-free, even
		"Ａ７ＫＱ２-Ｍ３ＸＺＰ-９ＲＴＢ４",                   // fullwidth
		"A7KQ2​-M3XZP-9RTB4‍-WQ8LN",           // zero-width inside
		"\U0001d400\U0001d7d5KQ2-M3XZP-9RTB4", // mathematical bold A, 7
		"a7kq2­m3xzp­9rtb4wq8ln",              // soft hyphens in a random token
	} {
		if out := sc.Scrub(v); out != Removed {
			t.Errorf("alone: %q -> %q", v, out)
		}
		if out := sc.Scrub("codes (" + v + "), keep safe"); out != "codes ("+Removed+"), keep safe" {
			t.Errorf("in text: %q -> %q", v, out)
		}
	}
	// Text with nothing to remove is returned as written, not folded.
	for _, in := range []string{"Привет, мир", "Сорок пять", "ＡＢＣ商事", "a well‑known–thing", "ΑΒΓ Δ"} {
		if out := sc.Scrub(in); out != in {
			t.Errorf("changed: %q -> %q", in, out)
		}
	}
}

// A code split across a fact's fields, or across consecutive facts, is
// removed with every part.
func TestSplitCodeFactsRemoved(t *testing.T) {
	sc := NewScrubber(nil)
	for _, f := range []Fact{
		{"JMNOX-CPMGJ", "JYTLJ-OOYJG", "note"},
		{"account", "JMNOX-CPMGJ", "JYTLJ-OOYJG"},
		{"recovery code:", "A7KQ2 M3XZP", "9RTB4 WQ8LN"},
		{"a7kq2m3xzp9r", "continues", "tb4wq8lnx2k4"},
	} {
		got := sc.ScrubFacts([]Fact{f})[0]
		for _, part := range []string{f.Subject, f.Predicate, f.Object} {
			for _, g := range strings.FieldsFunc(part, func(r rune) bool { return r == '-' || r == ' ' }) {
				if len(g) >= 5 && strings.Contains(got.Subject+"|"+got.Predicate+"|"+got.Object, g) && !keyWord[g] {
					t.Errorf("%+v kept %q: %+v", f, g, got)
				}
			}
		}
	}
	fs := sc.ScrubFacts([]Fact{{"account", "code_part_1", "JMNOX-CPMGJ"}, {"account", "code_part_2", "JYTLJ-OOYJG"}})
	if fs[0].Object != Removed || fs[1].Object != Removed {
		t.Errorf("across facts: %+v", fs)
	}
	// Unrelated neighbours stay.
	keep := []Fact{{"Mark", "lives in", "Berlin"}, {"Mark", "works at", "Example GmbH"}, {"order", "number", "1234-5678"}, {"order", "status", "shipped"}}
	if got := sc.ScrubFacts(keep); !equalFacts(got, keep) {
		t.Errorf("over-scrubbed: %+v", got)
	}
}

// keyWord lists the words of TestSplitCodeFactsRemoved's facts that are not
// code groups.
var keyWord = map[string]bool{"account": true, "recovery": true, "code:": true, "continues": true}

func equalFacts(a, b []Fact) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Ingest stores no part of a code split across consecutive facts.
func TestSplitCodeAcrossFactsNotStored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recall")
	st, err := OpenDir(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ix := open(t, st)
	// leakedCode cut into three facts of two groups each; no part is a code
	// by its shape alone.
	parts := strings.Split(leakedCode, "-")
	var facts []Fact
	for i := 0; i < len(parts); i += 2 {
		facts = append(facts, Fact{"account", "code_part", parts[i] + "-" + parts[i+1]})
	}
	id := mustIngest(t, ix, Item{Source: Source{Kind: "mail", Ref: "<split@x>"}, Text: "see facts", Facts: facts})
	data := string(readDir(t, path))
	for _, p := range parts {
		if strings.Contains(data, p) {
			t.Fatalf("stored group %q", p)
		}
	}
	it, _ := ix.Get(id)
	for _, f := range it.Facts {
		if f.Object != Removed {
			t.Fatalf("returned: %+v", it.Facts)
		}
	}
}

// A digit-free base32 TOTP seed with no context is removed by the letters
// floor (R11), in either case, padded or not, and through confusables.
func TestTOTPSeedWithoutContextRemoved(t *testing.T) {
	r := canaryRand(t)
	sc := NewScrubber(nil)
	for i := 0; i < 2000; i++ {
		seed := pick(r, b32[:26], 32)
		for _, v := range []string{seed, strings.ToLower(seed), seed + "======", withConfusables(r, seed)} {
			if out := sc.Scrub(v); out != Removed {
				t.Fatalf("alone: %q -> %q", v, out)
			}
			if out, want := sc.Scrub("add "+v+" to the app"), "add "+Removed+" to the app"; out != want {
				t.Fatalf("in text: %q -> %q", v, out)
			}
		}
	}
}

// confusableOf maps ASCII letters and digits to look-alikes the scrubber folds.
var confusableOf = map[byte][]string{
	'A': {"А", "Α", "Ａ"}, 'B': {"В", "Β"}, 'C': {"С", "Ｃ"}, 'E': {"Е", "Ε"},
	'H': {"Н", "Η"}, 'I': {"І", "Ι"}, 'K': {"К", "Κ"}, 'M': {"М", "Μ"},
	'N': {"Ν"}, 'O': {"О", "Ο"}, 'P': {"Р", "Ρ"}, 'T': {"Т", "Τ"},
	'X': {"Х", "Χ"}, 'Y': {"Υ", "Ү"}, 'Z': {"Ζ"}, 'S': {"Ѕ"}, 'J': {"Ј"},
	'a': {"а"}, 'c': {"с"}, 'e': {"е"}, 'o': {"о", "ο"}, 'p': {"р"},
	'x': {"х"}, 'y': {"у"}, 'i': {"і"}, 's': {"ѕ"}, 'j': {"ј"}, 'h': {"һ"},
	'0': {"０", "\U0001d7ce"}, '7': {"７", "\U0001d7d5"},
}

// withConfusables swaps about a third of the characters of v that have a
// look-alike, and adds a zero-width space now and then.
func withConfusables(r interface{ IntN(int) int }, v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if alts := confusableOf[v[i]]; len(alts) > 0 && r.IntN(3) == 0 {
			b.WriteString(alts[r.IntN(len(alts))])
		} else if c := v[i]; c >= 'a' && c <= 'z' && r.IntN(5) == 0 {
			b.WriteRune(rune(c) - 'a' + 0xff41) // fullwidth
		} else {
			b.WriteByte(v[i])
		}
		if r.IntN(12) == 0 {
			b.WriteString("​")
		}
	}
	return b.String()
}

// Property: TestGroupedCodesRemoved's codes stay removed under every separator
// and confusable mapping. Unicode dashes fold to '-', so every such code is
// removed alone; '.' and '_' codes alone when they hold a digit or 16+ letters
// (R11's floor); and every code, spaces included, after a recovery code key.
func TestGroupedCodesRemovedAnySeparator(t *testing.T) {
	r := canaryRand(t)
	alphabets := []string{b32, b32[:26], strings.ToLower(b32[:26]), "0123456789", "ABCDEFGH", "JMNOXY", "ab12"}
	dashes := []string{"-", "‐", "‑", "‒", "–", "—", "―", "−", "﹘", "﹣", "－"}
	others := []string{".", "_"}
	spaces := []string{" ", " ", " ", " ", " ", " ", "　"}
	sc := NewScrubber(nil)
	for i := 0; i < 20000; i++ {
		a := alphabets[r.IntN(len(alphabets))]
		n, size := 3+r.IntN(6), 4+r.IntN(5)
		groups := make([]string, n)
		for g := range groups {
			groups[g] = pick(r, a, size)
		}
		plain := strings.Join(groups, "")
		for g := range groups {
			groups[g] = withConfusables(r, groups[g])
		}
		var alone []string
		for _, s := range dashes {
			alone = append(alone, strings.Join(groups, s))
		}
		if hasDigit(plain) || len(plain) >= 16 {
			for _, s := range others {
				alone = append(alone, strings.Join(groups, s))
			}
		}
		for _, v := range alone {
			if out := sc.Scrub(v); out != Removed {
				t.Fatalf("alone: %q -> %q", v, out)
			}
			checkCodeInText(t, sc, v)
		}
		for _, s := range append(append(append([]string{}, dashes[:3]...), others...), spaces...) {
			v := strings.Join(groups, s)
			for _, key := range []string{"Your recovery code: ", "Backup codes:\n", "recovery codes are "} {
				if out, want := sc.Scrub(key+v+"\nThanks"), key+Removed+"\nThanks"; out != want {
					t.Fatalf("keyed: %q -> %q", key+v, out)
				}
			}
		}
	}
}
