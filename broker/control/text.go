package control

import (
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

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

// Agent text (CH-12, CH-21) keeps its characters, emoji and line breaks
// included, and goes in the encoding it needs: GSM-7 when every character
// is in GSM 03.38's basic set (line feed included) or its extension
// table, else UCS-2. One text is at most Segments concatenated segments:
// SegGSM7 septets each, an extension character costing two, or SegUCS2
// UTF-16 units each, an emoji outside the BMP costing two. These match
// modem.Segments, which the modem encodes with.
const (
	Segments = 3
	SegGSM7  = 153
	SegUCS2  = 67
)

// gsm7Ext is GSM 03.38's extension table, less form feed (a control
// character, which StripControls removes).
const gsm7Ext = "^{}\\[~]|€"

// Units is s's length in the encoding it needs: septets when gsm7, else
// UTF-16 units.
func Units(s string) (n int, isGSM7 bool) {
	isGSM7 = true
	for _, r := range s {
		switch {
		case r == '\n' || strings.ContainsRune(gsm7, r):
			n++
		case strings.ContainsRune(gsm7Ext, r):
			n += 2
		default:
			isGSM7 = false
		}
	}
	if !isGSM7 {
		n = len(utf16.Encode([]rune(s)))
	}
	return n, isGSM7
}

// Room is how many units one text holds: Segments segments of the
// encoding.
func Room(isGSM7 bool) int {
	if isGSM7 {
		return Segments * SegGSM7
	}
	return Segments * SegUCS2
}

// StripControls removes control characters (category Cc) other than line
// feed and the bidirectional controls (embeddings and overrides U+202A-E,
// isolates U+2066-9, marks U+200E, U+200F and U+061C) from agent text, so
// the order a phone shows is the order the CH-19 and CH-21 checks read
// (CH-12). A run of Cc between two characters that are not white space
// becomes one space, as it splits words where the text came from, so
// "code\r482913" still reads as a code word and a code; a bidi control is
// invisible and goes with no gap, so it cannot split a key (#2346). Every
// other character, joiners included, is kept.
func StripControls(s string) string {
	var b strings.Builder
	gap := false
	for _, r := range s {
		if r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 || r == 0x200E || r == 0x200F || r == 0x061C {
			continue
		}
		if r != '\n' && unicode.Is(unicode.Cc, r) {
			gap = true
			continue
		}
		if gap && b.Len() > 0 && !unicode.IsSpace(r) {
			if last, _ := utf8.DecodeLastRuneInString(b.String()); !unicode.IsSpace(last) {
				b.WriteByte(' ')
			}
		}
		gap = false
		b.WriteRune(r)
	}
	return b.String()
}

// FitAgent is Fit for agent text: it strips s (StripControls) and cuts it
// to one text in the encoding it needs, never inside a character or a
// joined emoji (Joinable). It never rewrites a character.
func FitAgent(s string) string {
	s = StripControls(s)
	n, g := Units(s)
	room := Room(g)
	if n <= room {
		return s
	}
	return s[:Prefix(s, room)]
}

// Prefix is the byte length of the longest start of s, cut where Joinable
// allows, that is at most units long in the encoding all of s needs. A
// start that is one joined run is cut on a rune boundary instead.
func Prefix(s string, units int) int {
	_, g := Units(s)
	n, p := 0, 0
	for i, r := range s {
		c := 1
		switch {
		case !g && r > 0xFFFF:
			c = 2
		case g && strings.ContainsRune(gsm7Ext, r):
			c = 2
		}
		if n+c > units {
			p = i
			break
		}
		n += c
		p = i + utf8.RuneLen(r)
	}
	atRune := p
	for p > 0 && p < len(s) && !Joinable(s, p) {
		_, w := utf8.DecodeLastRuneInString(s[:p])
		p -= w
	}
	if p == 0 {
		// One joined run longer than units: cut it on a rune boundary
		// sooner than send nothing.
		return atRune
	}
	return p
}

// Joinable says s may be cut at byte p: on a rune boundary, not before a
// joiner, variation selector, mark or skin tone, and not after a joiner,
// so an emoji built from several characters (👩‍💻) stays in one text.
func Joinable(s string, p int) bool {
	if p <= 0 || p >= len(s) {
		return true
	}
	if !utf8.RuneStart(s[p]) {
		return false
	}
	next, _ := utf8.DecodeRuneInString(s[p:])
	prev, _ := utf8.DecodeLastRuneInString(s[:p])
	return prev != '\u200d' && next != '\u200d' && !unicode.Is(unicode.Mn, next) && !unicode.Is(unicode.Me, next) &&
		!unicode.Is(unicode.Variation_Selector, next) && !(next >= 0x1F3FB && next <= 0x1F3FF)
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
