package owner

import (
	"strings"
	"unicode"
)

// skelRange is an inclusive range of code points.
type skelRange struct{ lo, hi rune }

// skelMaxPasses bounds SkeletonFold's iteration. TestCH12FoldPassesBounded
// shows every code point reaches its fixed point well within it.
const skelMaxPasses = 16

// SkeletonFolds returns the two CH-12 folds the CH-19 and CH-21 checks
// run on: dropped has every Default_Ignorable_Code_Point removed, spaced
// has each one read as a space, since a phone may draw one as nothing or
// as a gap. A check withholds the text if either matches.
func SkeletonFolds(s string) (dropped, spaced string) {
	return SkeletonFold(s, false), SkeletonFold(s, true)
}

// SkeletonFold is the CH-12 fold. One pass runs, in order: NFKD and full
// case folding; the UTS #39 skeleton (each code point replaced by its
// confusables.txt prototype, then NFD); NFKD and case folding again; every
// combining mark (category M) dropped; every Default_Ignorable_Code_Point
// dropped, or read as a space when ignorableAsSpace; every character that
// is not a letter, a digit or printable ASCII read as a space; and every
// run of spaces read as one. A single pass is not idempotent (U+13B7
// folds to "m", which folds to "rn"), so the pass repeats until the text
// stops changing. The result is therefore idempotent, and case-blind
// because case folding comes first; TestCH12FoldEveryCodePoint checks
// both for every code point.
//
// Every step but the last maps each code point on its own, so marks need
// no canonical reordering: they are all dropped, and no other step looks
// at its neighbours.
func SkeletonFold(s string, ignorableAsSpace bool) string {
	for i := 0; i < skelMaxPasses; i++ {
		next := skelPass(s, ignorableAsSpace)
		if next == s {
			return s
		}
		s = next
	}
	return s
}

// skelPasses reports how many passes SkeletonFold runs on s before the
// text stops changing (the last, unchanged pass not counted).
func skelPasses(s string, ignorableAsSpace bool) int {
	for i := 0; i < skelMaxPasses; i++ {
		next := skelPass(s, ignorableAsSpace)
		if next == s {
			return i
		}
		s = next
	}
	return skelMaxPasses
}

func skelPass(s string, ignorableAsSpace bool) string {
	s = skelMap(s, skelKF)
	s = skelMap(s, skelProto)
	s = skelMap(s, skelKF)
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.Is(unicode.M, r):
			continue
		case skelIgnorable(r):
			if !ignorableAsSpace {
				continue
			}
			r = ' '
		case !(r >= 0x20 && r < 0x7F || unicode.IsLetter(r) || unicode.IsDigit(r)):
			r = ' '
		}
		if r == ' ' {
			if space {
				continue
			}
			space = true
		} else {
			space = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// skelMap replaces each code point by its entry in m; a Hangul syllable
// with no entry is decomposed into its jamo, as NFKD and NFD do.
func skelMap(s string, m map[rune]string) string {
	var b strings.Builder
	for _, r := range s {
		if v, ok := m[r]; ok {
			b.WriteString(v)
			continue
		}
		if i := r - 0xAC00; i >= 0 && i < 11172 {
			b.WriteRune(0x1100 + i/588)
			b.WriteRune(0x1161 + i%588/28)
			if t := i % 28; t != 0 {
				b.WriteRune(0x11A7 + t)
			}
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func skelIgnorable(r rune) bool {
	lo, hi := 0, len(skelDICP)
	for lo < hi {
		m := (lo + hi) / 2
		switch {
		case r < skelDICP[m].lo:
			hi = m
		case r > skelDICP[m].hi:
			lo = m + 1
		default:
			return true
		}
	}
	return false
}
