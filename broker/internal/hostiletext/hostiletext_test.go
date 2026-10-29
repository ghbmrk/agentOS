package hostiletext

// REQ: KRN-2

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// recorder is a testing.TB that keeps what Run reports.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Helper()                   {}
func (r *recorder) Errorf(f string, a ...any) { r.errs = append(r.errs, fmt.Sprintf(f, a...)) }
func (r *recorder) has(sub string) bool       { return strings.Contains(strings.Join(r.errs, "\n"), sub) }
func run(accept func(string) bool, ex ...Except) *recorder {
	r := &recorder{TB: nil}
	Run(r, accept, ex...)
	return r
}

// strict is a check that refuses everything in the corpus: printable,
// valid UTF-8, no space and no default-ignorable or selector character.
func strict(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c == ' ' || !unicode.IsPrint(c) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, c) || unicode.Is(unicode.Variation_Selector, c) {
			return false
		}
	}
	return true
}

// A check that lets a zero-width name through fails Run, at each place the
// character sits; one that refuses the plain name fails the positive
// control; a strict check passes.
func TestRunFailsAnAcceptingCheck(t *testing.T) {
	zw := func(s string) bool { return strict(strings.ReplaceAll(s, "​", "")) }
	r := run(zw)
	for _, where := range []string{"leading", "inside", "trailing"} {
		if !r.has("accepts zero-width space U+200B " + where) {
			t.Errorf("Run did not report a zero-width name %s: %q", where, r.errs)
		}
	}
	if len(r.errs) != 3 { // alone is "" after the strip, which strict refuses
		t.Errorf("Run reported %d shapes, want 3: %q", len(r.errs), r.errs)
	}
	if r := run(func(string) bool { return false }); !r.has("positive control") {
		t.Errorf("a check refusing everything passed: %q", r.errs)
	}
	if r := run(strict); len(r.errs) != 0 {
		t.Errorf("a strict check failed: %q", r.errs)
	}
	for name, accept := range map[string]func(string) bool{
		"utf8 only": utf8.ValidString,
		"not blank": func(s string) bool { return strings.TrimSpace(s) != "" },
		"no ASCII cc": func(s string) bool {
			return s != "" && !strings.ContainsFunc(s, func(c rune) bool { return c < ' ' || c == 0x7f })
		},
		"IsPrint only": func(s string) bool {
			return s != "" && !strings.ContainsFunc(s, func(c rune) bool { return !unicode.IsPrint(c) })
		},
	} {
		if r := run(accept); len(r.errs) == 0 {
			t.Errorf("a %s check passed Run", name)
		}
	}
}

// An exception covers only the entry it names, and only with a reason; one
// naming no entry fails, so a renamed entry does not widen a check.
func TestExceptNamesAnEntryAndAReason(t *testing.T) {
	joiner := func(s string) bool { return strict(strings.ReplaceAll(s, "‍", "")) }
	if r := run(joiner); !r.has("zero-width joiner") {
		t.Fatalf("a joiner-accepting check passed: %q", r.errs)
	}
	if r := run(joiner, Except{"zero-width joiner U+200D": "emoji"}); len(r.errs) != 0 {
		t.Fatalf("an excepted joiner failed: %q", r.errs)
	}
	if r := run(joiner, Except{"zero-width joiner U+200D": " "}); !r.has("with no reason") {
		t.Fatalf("an exception with no reason passed: %q", r.errs)
	}
	if r := run(strict, Except{"zero-width joiner": "emoji"}); !r.has("no Hidden entry") {
		t.Fatalf("an exception naming no entry passed: %q", r.errs)
	}
}

// The corpus covers the kinds the brief names, and its source is plain
// ASCII, so a reviewer sees each entry as an escape, not as the character.
func TestCorpusIsComplete(t *testing.T) {
	src, err := os.ReadFile("hostiletext.go")
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range src {
		if b != '\n' && b != '\t' && (b < ' ' || b > '~') {
			t.Fatalf("hostiletext.go byte %d is %#x: write it as an escape", i, b)
		}
	}
	want := []rune{0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, '\r', '\n', 0x85, 0x2028, 0x2029, 0, 0x1b, 0x7f, 0x9b}
	for c := 0x202a; c <= 0x202e; c++ {
		want = append(want, rune(c))
	}
	for c := 0x2066; c <= 0x2069; c++ {
		want = append(want, rune(c))
	}
	have := map[string]bool{}
	for _, e := range Hidden {
		have[e.Text] = true
	}
	for _, c := range want {
		if !have[string(c)] {
			t.Errorf("Hidden has no entry for U+%04X", c)
		}
	}
	for _, s := range []string{"\xff", "\xc0\xaf", "\xed\xa0\x80"} {
		if !have[s] {
			t.Errorf("Hidden has no invalid UTF-8 %q", s)
		}
	}
	tag := false
	for _, e := range Hidden {
		if r, _ := utf8.DecodeRuneInString(e.Text); r >= 0xe0000 && r <= 0xe007f {
			tag = true
		}
	}
	if !tag || len(Blank) < 4 || Blank[0].Text != "" {
		t.Errorf("the corpus lacks a tag character or the blank entries")
	}
}
