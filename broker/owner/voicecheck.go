package owner

import (
	"log"
	"regexp"
	"strings"

	"github.com/ghbmrk/agentos/broker/control"
)

// HeldCode replaces agent text that mentions a code or takes the reply
// grammar (CH-21): only the broker's own texts ask for a code.
const HeldCode = "I held back a message because it mentioned a code. Read it on my Wi-Fi page."

// The vocabulary and the reply grammar are the spec's, not a model (ARC-2).
// Ordinary task text that uses the words is held; the spec says those
// false holds will be common until measured.
var voiceWordRE = regexp.MustCompile(`(?i)(?:\bcode generator\b|\bone-time\b|\b(?:code|passcode|pin|otp|authenticator|verification|grid|cell|password)\b)`)

// A control word followed by a request id or a 4 to 8 digit token.
var voiceGrammarRE = regexp.MustCompile(`(?i)\b(?:STOP|YES|NO|RUN|UNDO|MORE|HELP|STATUS|RESUME|UNLOCK|NAME)\s+(?:[A-Z][0-9]{1,2}|[0-9]{4,8})\b`)

var (
	voiceVocabulary = []string{"code generator", "one-time", "code", "passcode", "pin", "otp", "authenticator", "verification", "grid", "cell", "password"}
	voiceControls   = []string{"STOP", "YES", "NO", "RUN", "UNDO", "MORE", "HELP", "STATUS", "RESUME", "UNLOCK", "NAME"}
)

// The same three on the CH-12 folds (#2181), each literal replaced by its
// folds, since a fold changes the literals too (MORE folds to rnore, 0 to
// o). The fold maps space runs to one space.
var foldVoiceWordRE, foldVoiceGrammarRE, foldReplyYes, foldOrNo = func() (w, g, y, n *regexp.Regexp) {
	alt := func(lits []string) string {
		ps := make([]string, len(lits))
		for i, l := range lits {
			ps[i] = FoldPattern(l)
		}
		return "(?:" + strings.Join(ps, "|") + ")"
	}
	var letters, digits []string
	for c := 'a'; c <= 'z'; c++ {
		letters = append(letters, string(c))
	}
	for c := '0'; c <= '9'; c++ {
		digits = append(digits, string(c))
	}
	l, d := alt(letters), alt(digits)
	return regexp.MustCompile(`\b` + alt(voiceVocabulary) + `\b`),
		regexp.MustCompile(`\b` + alt(voiceControls) + ` +(?:` + l + d + `{1,2}|` + d + `{4,8})\b`),
		regexp.MustCompile(FoldPattern("reply yes")),
		regexp.MustCompile(FoldPattern("or no"))
}()

// VoiceShaped reports whether text, or any of its CH-12 folds, matches the
// CH-21 check: a word of the vocabulary, the reply grammar, or the
// reply-options footer, whose two halves count when they are in any folds.
func VoiceShaped(text string) bool {
	if voiceWordRE.MatchString(text) || voiceGrammarRE.MatchString(text) {
		return true
	}
	low := strings.ToLower(text)
	yes, no := strings.Contains(low, "reply yes"), strings.Contains(low, "or no")
	for _, f := range CheckFolds(text) {
		if foldVoiceWordRE.MatchString(f) || foldVoiceGrammarRE.MatchString(f) {
			return true
		}
		yes = yes || foldReplyYes.MatchString(f)
		no = no || foldOrNo.MatchString(f)
	}
	return yes && no
}

// AgentVoice reports whether agent text is VoiceShaped in the three
// readings AgentSecret uses, so a control character can neither split a
// word of the vocabulary nor join a control word to its request id.
func AgentVoice(text string) bool {
	return VoiceShaped(text) || VoiceShaped(control.StripControls(text)) || VoiceShaped(control.JoinControls(text))
}

// holdVoice logs a CH-21 hold. The text itself is not logged: it may
// carry the code it asks for.
func holdVoice() {
	log.Printf("owner channel: held agent text that mentioned a code (CH-21)")
}
