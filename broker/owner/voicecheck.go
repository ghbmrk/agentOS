package owner

import (
	"log"
	"regexp"
	"strings"

	"github.com/ghbmrk/agentos/broker/control"
)

// HeldCode replaces agent text that mentions a code or takes the reply
// grammar (CH-21) when it could not be kept for the owner page: only the
// broker's own texts ask for a code, and this one names no page.
// HeldCodePointer, CH-21's held text, replaces it once it is kept
// (keep.go).
const (
	HeldCode        = "I held back a message because it mentioned a code, and I could not keep it. Ask me to put it another way."
	HeldCodePointer = "I held back a message because it mentioned a code. Read it on my Wi-Fi page."
)

// The vocabulary and the reply grammar are the spec's, not a model (ARC-2).
// Ordinary task text that uses the words is held; the spec says those
// false holds will be common until measured. A word's plural counts too
// ("codes", "PINs"). "digit" joined the vocabulary through the
// adversarial set (HLD-5, Security on #3916): "send the 6 digits from
// your app" asks for a code without a word of the spec's list.
var (
	voicePhrases  = []string{"code generator", "one-time"}
	voiceWords    = []string{"code", "passcode", "pin", "otp", "authenticator", "verification", "grid", "cell", "password", "digit"}
	voiceControls = []string{"STOP", "YES", "NO", "RUN", "UNDO", "MORE", "HELP", "STATUS", "RESUME", "UNLOCK", "NAME"}
)

// voiceSep is what may stand between the letters of a one-word term of
// the vocabulary: up to three characters that are neither letters nor
// digits, so "c.o.d.e", "pass-word" and "pass word" read as the word
// (Security on #3916). The two phrases keep their own separator, so "one
// time" alone is ordinary text.
const voiceSep = `[^\pL\pN]{0,3}`

// spaced is words as one alternation, each one-word term with voiceSep
// between its characters, each character written by char.
func spaced(words []string, char func(rune) string) string {
	ps := make([]string, len(words))
	for i, w := range words {
		cs := make([]string, 0, len(w))
		for _, c := range w {
			cs = append(cs, char(c))
		}
		ps[i] = strings.Join(cs, voiceSep)
	}
	return strings.Join(ps, "|")
}

var voiceWordRE = regexp.MustCompile(`(?i)\b(?:` + strings.Join(voicePhrases, "|") + `|` +
	spaced(voiceWords, func(c rune) string { return regexp.QuoteMeta(string(c)) }) + `)s?\b`)

// A control word followed by a request id or a 4 to 8 digit token, or
// UNLOCK or RESUME followed by a challenge (CH-11's "UNLOCK HKMP": four
// of the challenge alphabet, which has no I, O, 0 or 1).
var voiceGrammarRE = regexp.MustCompile(`(?i)\b(?:(?:STOP|YES|NO|RUN|UNDO|MORE|HELP|STATUS|RESUME|UNLOCK|NAME)` + voiceGap + `(?:[A-Z][0-9]{1,2}|[0-9]{4,8})|(?:UNLOCK|RESUME)` + voiceGap + `[A-HJ-NP-Z2-9]{4})\b`)

// voiceGap is the gap between the words of the reply grammar and the
// footer: any run of runes that are not wordRunes, as the reply parser
// reads one (parse.go fields), so "YES, K7", "(YES) K7" and "Reply 'YES'
// or 'NO'" read as the owner's parser reads them (Security on #4017).
// The patterns' \b edges are ASCII and count "_" as a letter, so
// VoiceShaped also runs them on parserGaps of each reading, where every
// separator the parser knows ("_YES K7_", "YES² K7") is a space.
const voiceGap = `[^\pL\p{Nd}]+`

// The footer's two halves, as written.
var voiceReplyYes, voiceOrNo = regexp.MustCompile(`(?i)\breply` + voiceGap + `yes\b`), regexp.MustCompile(`(?i)\bor` + voiceGap + `no\b`)

// challengeAlphabet is the UNLOCK challenge's (reaction.go carriesCode).
const challengeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// voiceOpeningRE is a line that opens like a broker request: a
// request-ID-shaped token (a letter, a digit, and up to two more letters
// or digits, so "R7" and "R7K2") followed by ":", after anything that is
// neither a letter nor a digit ("> R7:", "\"R7:").
var voiceOpeningRE = regexp.MustCompile(`(?i)^[^\pL\p{Nd}]*[A-Z][0-9][A-Z0-9]{0,2}[^\pL\p{Nd}:]*:`)

// The same on the CH-12 folds (#2181), each literal replaced by its
// folds, since a fold changes the literals too (MORE folds to rnore, 0 to
// o). The fold maps space runs to one space. The challenge is matched in
// its own alphabet's folds and the opening's digit as a digit: the
// digits' folds take o and l for 0 and 1, so "work" would read as a
// challenge and "Note:" as a request.
var foldVoiceWordRE, foldVoiceGrammarRE, foldVoiceOpening, foldReplyYes, foldOrNo = func() (w, g, o, y, n *regexp.Regexp) {
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
	words := spaced(voiceWords, func(c rune) string { return FoldPattern(string(c)) })
	return regexp.MustCompile(`\b(?:` + alt(voicePhrases) + `|` + words + `)(?:` + FoldPattern("s") + `)?\b`),
		regexp.MustCompile(`\b(?:` + alt(voiceControls) + voiceGap + `(?:` + l + d + `{1,2}|` + d + `{4,8})|` +
			alt([]string{"UNLOCK", "RESUME"}) + voiceGap + alt(strings.Split(challengeAlphabet, "")) + `{4})\b`),
		regexp.MustCompile(`^[^\pL\p{Nd}]*` + l + `[0-9](?:` + l + `|[0-9]){0,2}[^\pL\p{Nd}:]*:`),
		regexp.MustCompile(`\b` + FoldPattern("reply") + voiceGap + FoldPattern("yes") + `\b`),
		regexp.MustCompile(`\b` + FoldPattern("or") + voiceGap + FoldPattern("no") + `\b`)
}()

// VoiceShaped reports whether text, or any of its CH-12 folds, matches the
// CH-21 check: a word of the vocabulary, the reply grammar, a line that
// opens like a broker request, or the reply-options footer, whose two
// halves count when they are in any folds.
func VoiceShaped(text string) bool {
	if opensLikeRequest(text) {
		return true
	}
	var yes, no bool
	for _, t := range []string{text, parserGaps(text)} {
		if voiceWordRE.MatchString(t) || voiceGrammarRE.MatchString(t) {
			return true
		}
		yes = yes || voiceReplyYes.MatchString(t)
		no = no || voiceOrNo.MatchString(t)
	}
	for _, f := range CheckFolds(text) {
		for _, t := range []string{f, parserGaps(f)} {
			if foldVoiceWordRE.MatchString(t) || foldVoiceGrammarRE.MatchString(t) {
				return true
			}
			yes = yes || foldReplyYes.MatchString(t)
			no = no || foldOrNo.MatchString(t)
		}
	}
	return yes && no
}

// opensLikeRequest reports whether any line of text, as written or in
// any of its folds, opens like a broker request (voiceOpeningRE). Each
// line is folded alone, since the fold reads a line break as a space. A
// line ends at any character a phone may draw as a line break, the line
// and paragraph separators (U+2028, U+2029) too, which StripControls
// keeps (L3 on #4017).
func opensLikeRequest(text string) bool {
	lines := strings.FieldsFunc(text, func(r rune) bool {
		switch r {
		case '\n', '\r', '\v', '\f', '\u0085', '\u2028', '\u2029':
			return true
		}
		return false
	})
	for _, line := range lines {
		if voiceOpeningRE.MatchString(line) {
			return true
		}
		for _, f := range CheckFolds(line) {
			if foldVoiceOpening.MatchString(f) {
				return true
			}
		}
	}
	return false
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
