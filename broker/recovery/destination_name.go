package recovery

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// validName checks a destination's form: 1 to 200 runes of letters,
// digits, spaces and plain punctuation. No ':', '@', '?', '#', '%' or '\\',
// so no URL, share path, user info or query can carry a sign-in, in any
// spelling (L3 on #80). The limit is in runes. Letters must share one script
// so look-alike characters from another alphabet cannot hide a second
// meaning (BAK-1 follow-up on #80; single-script rule).
func validName(d string) error {
	if d == "" || strings.TrimSpace(d) != d {
		return ErrBadBackupChoice
	}
	if utf8.RuneCountInString(d) > 200 {
		return ErrBadBackupChoice
	}
	var saw *unicode.RangeTable
	for _, r := range d {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || strings.ContainsRune("-_.,()'/+&", r)) {
			return ErrBadBackupChoice
		}
		if !unicode.IsLetter(r) {
			continue
		}
		rt := letterScript(r)
		if rt == nil {
			return ErrBadBackupChoice
		}
		if saw == nil {
			saw = rt
		} else if saw != rt {
			return ErrBadBackupChoice
		}
	}
	return nil
}

// letterScript is the primary script table for r, or nil when the rune is
// not a letter we accept in a destination name.
func letterScript(r rune) *unicode.RangeTable {
	for _, rt := range []*unicode.RangeTable{
		unicode.Latin, unicode.Greek, unicode.Cyrillic, unicode.Han,
		unicode.Hiragana, unicode.Katakana, unicode.Hangul, unicode.Arabic,
		unicode.Hebrew, unicode.Devanagari, unicode.Thai,
	} {
		if unicode.Is(rt, r) {
			return rt
		}
	}
	return nil
}
