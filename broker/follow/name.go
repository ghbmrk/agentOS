package follow

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/ghbmrk/agentos/broker/owner"
)

// The owner's name for a source: 1 to MaxName printable characters on one
// line, no leading or trailing space, and at most MaxNameDigits digits, so
// the name can carry a year but never a code, even spaced out (security
// R1 on #180; codes are 6 digits). It reaches the owner in broker-voiced
// texts.
const (
	MaxName       = 40
	MaxNameDigits = 4
)

// lookAlike matches the project's name in any of the CH-12 folds (case,
// accents, confusable skeletons, ignorable characters), with or without
// its space, so a named follow never reads as switching back (#957).
var lookAlike = []*regexp.Regexp{
	regexp.MustCompile(owner.FoldPattern("agentos project")),
	regexp.MustCompile(owner.FoldPattern("agentosproject")),
}

// NameOK reports whether name is one a named follow may carry: the length,
// character and digit rules above, and no look-alike of the project's own
// name (#957, CH-10).
func NameOK(name string) bool {
	n, digits := 0, 0
	for _, c := range name {
		if !unicode.IsPrint(c) {
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
		for _, re := range lookAlike {
			if re.MatchString(f) {
				return false
			}
		}
	}
	return true
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
