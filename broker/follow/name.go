package follow

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/owner"
)

// The owner's name for a source: 1 to MaxName printable characters of valid
// UTF-8 on one line, none of them default-ignorable (a filler, a grapheme
// joiner) or a variation selector, no leading or trailing space, and at most MaxNameDigits digits, so
// the name can carry a year but never a code, even spaced out (security
// R1 on #180; codes are 6 digits). It reaches the owner in broker-voiced
// texts.
const (
	MaxName       = 40
	MaxNameDigits = 4
)

// lookAlike matches the project's name in any of the CH-12 folds (case,
// accents, confusable skeletons, ignorable characters) once every
// character that is not a letter or a digit is dropped, so no space,
// punctuation or split word ("Agent OS-Project") hides it and a named
// follow never reads as switching back (#957).
var lookAlike = regexp.MustCompile(owner.FoldPattern("agentosproject"))

// NameOK reports whether name is one a named follow may carry: the length,
// character and digit rules above, and no look-alike of the project's own
// name (#957, CH-10).
func NameOK(name string) bool {
	if !utf8.ValidString(name) {
		return false
	}
	n, digits := 0, 0
	for _, c := range name {
		if !unicode.IsPrint(c) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, c) || unicode.Is(unicode.Variation_Selector, c) {
			return false
		}
		if unicode.IsDigit(c) {
			digits++
		}
		n++
	}
	if n == 0 || n > MaxName || digits > MaxNameDigits || strings.TrimSpace(name) != name {
		return false
	}
	for _, f := range append(owner.CheckFolds(name), strings.ToLower(name)) {
		if lookAlike.MatchString(strings.Map(alnum, f)) {
			return false
		}
	}
	return true
}

// alnum keeps letters and digits and drops every other character.
func alnum(r rune) rune {
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return r
	}
	return -1
}

// DigestOK reports whether s is a root summary's digest as Describe gives
// it: 64 lower-case hex characters.
func DigestOK(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
