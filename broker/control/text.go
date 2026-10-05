package control

import "strings"

// MaxText is three concatenated GSM-7 segments of 153 characters (CH-12).
const MaxText = 3 * 153

// gsm7 is the GSM 03.38 basic character set, minus escape and control
// characters. Broker texts use nothing else (CH-12).
const gsm7 = "@£$¥èéùìòÇØøÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?" +
	"¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"

// IsGSM7 reports whether s uses only the GSM-7 basic set.
func IsGSM7(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune(gsm7, r) {
			return false
		}
	}
	return true
}

// Fit replaces characters outside GSM-7 and cuts s to MaxText.
func Fit(s string) string {
	b := []rune(strings.Map(func(r rune) rune {
		if strings.ContainsRune(gsm7, r) {
			return r
		}
		return '?'
	}, s))
	var out []rune
	n := 0
	for _, r := range b {
		// MaxText counts bytes too, so a reply never exceeds it in
		// either unit; the few two-byte GSM-7 letters cost one more.
		if n+len(string(r)) > MaxText {
			break
		}
		out = append(out, r)
		n += len(string(r))
	}
	return string(out)
}

// safeToken keeps only [A-Za-z._/@-], cut to max characters. Field values
// that did not come from the broker's own templates are rendered through it,
// so they cannot carry line breaks, spaced control words, or digit codes into
// a text (CH-12, CH-19).
func safeToken(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r == '.', r == '_', r == '/', r == '@', r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// plainLine keeps letters, digits, spaces, and . , ; : ( ) - only, cut to max
// characters: no line breaks and nothing that could start a reply grammar
// on a new line. It is for broker template lines that carry counts.
func plainLine(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == ' ', r == '.', r == ',', r == ';', r == ':', r == '(', r == ')', r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}
