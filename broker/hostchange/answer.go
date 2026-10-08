package hostchange

import (
	"strings"
	"unicode"
)

// AsksRecoveryPrompt reports whether the owner is asking about a Windows
// recovery-key / BitLocker prompt after using AgentOS (HOST-1c part 2).
// The box answers only from the owner's guide section RecoveryPromptHeading.
func AsksRecoveryPrompt(msg string) bool {
	f := foldWords(msg)
	if f == "" {
		return false
	}
	hasKey := strings.Contains(f, "recovery key") || strings.Contains(f, "bitlocker") ||
		strings.Contains(f, "recoverykey")
	hasAsk := strings.Contains(f, "ask") || strings.Contains(f, "prompt") ||
		strings.Contains(f, "want") || strings.Contains(f, "need") ||
		strings.Contains(f, "what") || strings.Contains(f, "why") ||
		strings.Contains(f, "help") || strings.Contains(f, "windows")
	return hasKey && hasAsk
}

func foldWords(s string) string {
	var b strings.Builder
	prevSpace := true
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			prevSpace = false
		} else if !prevSpace {
			b.WriteByte(' ')
			prevSpace = true
		}
	}
	return strings.TrimSpace(b.String())
}

// RecoveryPromptAnswer is the guide section body under RecoveryPromptHeading,
// trimmed for an owner text. guide is the full owners-guide.md contents.
// Empty if the section is missing.
func RecoveryPromptAnswer(guide string) string {
	_, rest, ok := strings.Cut(guide, "\n## "+RecoveryPromptHeading+"\n")
	if !ok {
		return ""
	}
	body, _, _ := strings.Cut(rest, "\n## ")
	return strings.TrimSpace(body)
}
