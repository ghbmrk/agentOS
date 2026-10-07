// Package voice checks owner-facing broker text for CH-21 first-person voice.
package voice

import (
	"regexp"
	"strings"
)

// thirdPerson matches broker self-references that must become first person
// ("I …") or be unsigned (CH-21, UX V4).
var thirdPerson = regexp.MustCompile(`(?i)(?:\bthe box\b|\bthis box\b|\bthe agent\b|^agent:\s|\sagent:\s)`)

// OK reports whether s has no third-person self-reference.
func OK(s string) bool { return !thirdPerson.MatchString(strings.TrimSpace(s)) }

// Hits returns each matched self-reference in s.
func Hits(s string) []string {
	return thirdPerson.FindAllString(s, -1)
}
