package owner

import (
	"math/rand"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// REQ: CH-12

// variants are the two Default_Ignorable_Code_Point readings CH-12 checks.
var variants = []struct {
	name    string
	asSpace bool
}{{"dropped", false}, {"spaced", true}}

// TestCH12FoldTablesMatchGoUnicode: the tables and Go's unicode package
// (which supplies M, letters and digits) are the same Unicode version.
func TestCH12FoldTablesMatchGoUnicode(t *testing.T) {
	if unicode.Version != skelUnicodeVersion {
		t.Fatalf("Go unicode %s, fold tables %s: regenerate with gen_skelfold.go", unicode.Version, skelUnicodeVersion)
	}
}

// TestCH12FoldEveryCodePoint scans every code point, in both readings,
// for fold(fold(x)) = fold(x) and fold(upper(x)) = fold(lower(x)) =
// fold(x), and for the pass bound: the deepest chain any code point
// needs stays at most half the cap, so the cap never stops the iteration.
func TestCH12FoldEveryCodePoint(t *testing.T) {
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			bad, deepest := 0, 0
			for r := rune(0); r <= unicode.MaxRune; r++ {
				if r >= 0xD800 && r <= 0xDFFF {
					continue
				}
				x := string(r)
				f := SkeletonFold(x, v.asSpace)
				if n := skelPasses(x, v.asSpace); n > deepest {
					deepest = n
				}
				if !utf8.ValidString(f) {
					t.Errorf("U+%04X: invalid UTF-8 %q", r, f)
				}
				for _, c := range []struct{ name, in string }{
					{"fold", f},
					{"upper", strings.ToUpper(x)},
					{"lower", strings.ToLower(x)},
					{"title", string(unicode.ToTitle(r))},
				} {
					if g := SkeletonFold(c.in, v.asSpace); g != f {
						if bad++; bad <= 20 {
							t.Errorf("U+%04X %q: fold(%s(x)) = %q, fold(x) = %q", r, x, c.name, g, f)
						}
					}
				}
			}
			if bad > 0 {
				t.Errorf("%d failures", bad)
			}
			if deepest > skelMaxPasses/2 {
				t.Errorf("a code point needs %d passes; the cap %d leaves too little margin", deepest, skelMaxPasses)
			}
		})
	}
}

// TestCH12FoldReviewCases: the code points and texts named on #2162,
// including the 82 a single pass leaves unstable.
func TestCH12FoldReviewCases(t *testing.T) {
	singles := []rune{
		0x237A, 0x2376, 0x2800, 0x3164, 0x115F, 0x1160, 0xFFA0,
		0x13B7, 0xAB87, 0x16D6, 0xA4DF, 0x23E8, 0x0025, 0x2030, 0x2031, 0xFF05,
		0x03DA, 0x03DB, 0x2C8A, 0x2C8B, 0x1260, 0x2229, 0x13B1, 0x14A5, 0x16A6,
	}
	for _, v := range variants {
		for _, r := range singles {
			x := string(r)
			f := SkeletonFold(x, v.asSpace)
			if g := SkeletonFold(f, v.asSpace); g != f {
				t.Errorf("%s U+%04X: fold %q, fold(fold) %q", v.name, r, f, g)
			}
			if u, l := SkeletonFold(strings.ToUpper(x), v.asSpace), SkeletonFold(strings.ToLower(x), v.asSpace); u != f || l != f {
				t.Errorf("%s U+%04X: fold %q, upper %q, lower %q", v.name, r, f, u, l)
			}
		}
	}
	// Blank-looking characters (U+2800, Hangul fillers) never survive as
	// text: they fold to a space or to nothing.
	for _, r := range []rune{0x2800, 0x3164, 0x115F, 0x1160, 0xFFA0} {
		for _, v := range variants {
			if f := SkeletonFold("A"+string(r)+"B", v.asSpace); f != SkeletonFold("A B", v.asSpace) && f != SkeletonFold("AB", v.asSpace) {
				t.Errorf("%s U+%04X: A_B folds to %q", v.name, r, f)
			}
		}
	}
}

// TestCH12FoldMultiCharacter: texts that must fold the same as the reply
// they imitate, under both readings where the reading matters.
func TestCH12FoldMultiCharacter(t *testing.T) {
	same := []struct{ attack, plain string }{
		{"ᎷORE A7", "MORE A7"}, // Cherokee MV: a single pass gives "rnore a7" vs "more a7"
		{"ᎩᎬᏚ A7", "YES A7"},   // Cherokee GI E DU
		{"YES ⍶7", "YES A7"},   // APL alpha underbar
		{"YES ⍺7", "YES A7"},   // APL alpha
		{"YES⠀A7", "YES A7"},   // braille blank
		{"Y̲ES A7", "YES A7"},  // combining low line
		{"Y‍ES A7", "YES A7"},  // ZWJ inside the code word, dropped reading
		{"YES   A7", "YES A7"}, // a run of spaces is one
		{"yes a7", "YES A7"},
		{"ＹＥＳ Ａ７", "YES A7"}, // fullwidth
		{"YES\nA7", "YES A7"},
	}
	for _, c := range same {
		if a, p := SkeletonFold(c.attack, false), SkeletonFold(c.plain, false); a != p {
			t.Errorf("dropped %q: %q, want %q (fold of %q)", c.attack, a, p, c.plain)
		}
	}
	// In the spaced reading a ZWJ inside a word splits it, as a phone
	// that draws it as a gap would show it.
	if a, p := SkeletonFold("Y‍ES A7", true), SkeletonFold("Y ES A7", true); a != p {
		t.Errorf("spaced ZWJ: %q, want %q", a, p)
	}
	d, s := SkeletonFolds("NO⁠A7")
	if d != SkeletonFold("NOA7", false) || s != SkeletonFold("NO A7", true) {
		t.Errorf("SkeletonFolds(NO WJ A7) = %q, %q", d, s)
	}
}

// TestCH12FoldTextsIdempotentAndCaseBlind: random texts drawn from every
// plane, from the code points the review cases name, and from spaces and
// ignorables, so the per-code-point scan's result carries to texts where
// runs of spaces join across neighbours.
func TestCH12FoldTextsIdempotentAndCaseBlind(t *testing.T) {
	rng := rand.New(rand.NewSource(2162))
	pool := []rune{' ', ' ', '‍', '⁠', 'ㅤ', '⠀', '̲', 'm', 'M', 'r', 'n',
		0x13B7, 0x23E8, '%', 0x03DA, 0x1260, 0x13B1, 0x16A6, 'A', '7', 0x0130, 0x0131, 0x017F, 0x1E9E, 0xFB03}
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := rng.Intn(12); n >= 0; n-- {
			var r rune
			if rng.Intn(2) == 0 {
				r = pool[rng.Intn(len(pool))]
			} else {
				r = rune(rng.Intn(unicode.MaxRune + 1))
				if r >= 0xD800 && r <= 0xDFFF {
					r = 'x'
				}
			}
			b.WriteRune(r)
		}
		x := b.String()
		for _, v := range variants {
			f := SkeletonFold(x, v.asSpace)
			if g := SkeletonFold(f, v.asSpace); g != f {
				t.Fatalf("%s %+q: fold %+q, fold(fold) %+q", v.name, x, f, g)
			}
			if u, l := SkeletonFold(strings.ToUpper(x), v.asSpace), SkeletonFold(strings.ToLower(x), v.asSpace); u != f || l != f {
				t.Fatalf("%s %+q: fold %+q, upper %+q, lower %+q", v.name, x, f, u, l)
			}
		}
	}
}
