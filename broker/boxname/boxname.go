// Package boxname is the name check for the box's one name (SPEC CH-21):
// the name the owner keeps or types at setup and changes with NAME
// (CH-11). Third parties always see it with the suffix the broker appends,
// so the check keeps the name from posing as that suffix, as a control
// word, or as the owner.
package boxname

import (
	"errors"
	"strings"
	"unicode"
)

// MaxLen is the longest name, in characters.
const MaxLen = 32

// The ways a name fails the check. Each Error is an owner-facing reason.
var (
	ErrShape       = errors.New("a name is 1 to 32 letters, spaces, hyphens and apostrophes")
	ErrControlWord = errors.New("that is one of my control words")
	ErrReserved    = errors.New(`a name cannot contain "AgentOS" or "assistant"`)
	ErrOwnerName   = errors.New("that is your own name")
)

// controlWords is CH-11's closed set, with the pause and revoke words
// (ADP-9) and the loop words (LOOP-0).
var controlWords = map[string]bool{
	"STOP": true, "RESUME": true, "STATUS": true, "HELP": true, "YES": true, "NO": true,
	"UNDO": true, "MORE": true, "PUBLIC": true, "RUN": true, "UNLOCK": true, "NAME": true,
	"PAUSE": true, "REVOKE": true, "LOOP": true, "LOOPS": true,
}

// reserved are words the name cannot contain, compared on letters only
// and ignoring case, so "Agent OS" and "Assist-ant" count.
var reserved = []string{"agentos", "assistant"}

// normal trims the name and collapses runs of spaces.
func normal(name string) string {
	return strings.Join(strings.FieldsFunc(name, func(r rune) bool { return r == ' ' }), " ")
}

// Shape reports whether name, trimmed, is 1 to MaxLen letters, spaces,
// hyphens and apostrophes with at least one letter. It is the syntactic
// part of Check.
func Shape(name string) bool {
	n := normal(name)
	if n == "" || len([]rune(n)) > MaxLen {
		return false
	}
	letter := false
	for _, r := range n {
		switch {
		case unicode.IsLetter(r):
			letter = true
		case r == ' ', r == '-', r == '\'', r == '’':
		default:
			return false
		}
	}
	return letter
}

// letters is s's letters only, lower-cased.
func letters(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, s)
}

// Check returns name trimmed, with runs of spaces collapsed, if it may be
// the box's name. owner is the owner's name, "" when unknown.
func Check(name, owner string) (string, error) {
	if !Shape(name) {
		return "", ErrShape
	}
	n := normal(name)
	l := letters(n)
	if controlWords[strings.ToUpper(l)] {
		return "", ErrControlWord
	}
	for _, w := range reserved {
		if strings.Contains(l, w) {
			return "", ErrReserved
		}
	}
	if o := letters(owner); o != "" && o == l {
		return "", ErrOwnerName
	}
	return n, nil
}
