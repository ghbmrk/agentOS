// Package boxname is the box's name and first-person voice rules (CH-21).
package boxname

import (
	"strings"
	"unicode"
)

// MaxLen is the longest allowed box name (CH-21).
const MaxLen = 32

// controlWords are CH-11 words a box name must not be.
var controlWords = map[string]bool{
	"STOP": true, "RESUME": true, "STATUS": true, "HELP": true,
	"YES": true, "NO": true, "UNDO": true, "MORE": true,
	"PUBLIC": true, "RUN": true, "UNLOCK": true, "NAME": true,
	"PAUSE": true, "REVOKE": true, "LOOPS": true,
}

// Check reports whether name is a valid box name (CH-21).
// owner, when non-empty, is the owner's own name; the box name must not
// equal it (case-insensitive, space-folded).
func Check(name, owner string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > MaxLen {
		return false
	}
	for _, r := range name {
		switch {
		case unicode.IsLetter(r), r == ' ', r == '-', r == '\'':
		default:
			return false
		}
	}
	folded := fold(name)
	if controlWords[strings.ToUpper(folded)] {
		return false
	}
	if strings.Contains(folded, "agentos") || strings.Contains(folded, "assistant") {
		return false
	}
	if owner != "" && fold(owner) == folded {
		return false
	}
	return true
}

func fold(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ThirdParty is how the box names itself to others (CH-21):
// "<name> (<owner>'s AgentOS assistant)". owner may be empty.
func ThirdParty(name, owner string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "AgentOS"
	}
	if strings.TrimSpace(owner) == "" {
		return name + " (an AgentOS assistant)"
	}
	return name + " (" + strings.TrimSpace(owner) + "'s AgentOS assistant)"
}

// AskForCode reports whether agent text asks the owner for a code,
// password, PIN, or similar (CH-21 / A14): withheld from the owner.
func AskForCode(text string) bool {
	f := foldWords(text)
	needles := []string{
		"code", "otp", "pin", "password", "passphrase", "passcode",
		"2fa", "verification", "authenticator", "totp",
	}
	asks := []string{"send", "tell", "give", "share", "enter", "type", "reply", "text", "what is", "what's"}
	hasNeedle := false
	for _, n := range needles {
		if strings.Contains(f, n) {
			hasNeedle = true
			break
		}
	}
	if !hasNeedle {
		return false
	}
	for _, a := range asks {
		if strings.Contains(f, a) {
			return true
		}
	}
	// "your code" / "the code" without an ask verb still counts.
	return strings.Contains(f, "your code") || strings.Contains(f, "the code") ||
		strings.Contains(f, "your pin") || strings.Contains(f, "your password")
}

// ReplyGrammar reports whether agent text imitates the owner-channel
// reply grammar (YES/NO/RESUME/UNDO/MORE with an id or code) (CH-21 / A14).
func ReplyGrammar(text string) bool {
	line := strings.TrimSpace(text)
	if line == "" {
		return false
	}
	// First line only: a whole-message control shape.
	if i := strings.IndexAny(line, "\n\r"); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToUpper(r)
		}
		return ' '
	}, line))
	if len(f) == 0 {
		return false
	}
	switch f[0] {
	case "YES", "NO", "UNDO", "MORE", "RESUME", "UNLOCK", "RUN", "PAUSE", "REVOKE", "NAME":
		return true
	}
	return false
}

func foldWords(s string) string {
	var b strings.Builder
	prevSpace := true
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			prevSpace = false
			continue
		}
		if !prevSpace {
			b.WriteByte(' ')
			prevSpace = true
		}
	}
	return strings.TrimSpace(b.String())
}

// Withheld is what Notify journals and the owner sees when agent text is
// blocked (CH-21).
const Withheld = "I held back a message that asked for a code or looked like a reply to me."
