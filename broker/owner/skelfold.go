package owner

import (
	"regexp"
	"sort"
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
	return skelFold(s, ignorableAsSpace, false)
}

func skelFold(s string, ignorableAsSpace, protoFirst bool) string {
	for i := 0; i < skelMaxPasses; i++ {
		next := skelPass(s, ignorableAsSpace, protoFirst)
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
		next := skelPass(s, ignorableAsSpace, false)
		if next == s {
			return i
		}
		s = next
	}
	return skelMaxPasses
}

// skelPass is one pass of the fold; protoFirst also runs the prototype
// step before the first case folding (CheckFolds).
func skelPass(s string, ignorableAsSpace, protoFirst bool) string {
	if protoFirst {
		s = skelMap(s, skelProto)
	}
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

// skelWindow and skelOverlap bound each fold's input (#2181): a fold can
// grow its text about tenfold, so CheckFolds folds a text longer than
// skelWindow runes in windows of that many runes, each starting
// skelWindow-skelOverlap runes after the last, so every span of
// skelOverlap runes lies whole inside one window.
const (
	skelWindow  = 1024
	skelOverlap = 256
)

// CheckFolds returns, without repeats, the folds the CH-19 and CH-21
// checks run on besides the text itself (#2181): SkeletonFolds' two
// readings; the same two of the text with every combining mark dropped
// first, since case folding turns some marks into letters (U+0345 folds
// to ι); and the two readings of a fold whose pass runs the confusables
// prototype before case folding too, since case folding can lose a
// capital's shape (Greek Υ folds to υ, whose prototype is u, while Υ's
// own prototype is Y). A check withholds the text if any matches.
func CheckFolds(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, w := range skelWindows(s) {
		texts := []string{w}
		if m := strings.Map(dropMark, w); m != w {
			texts = append(texts, m)
		}
		for _, x := range texts {
			for _, protoFirst := range []bool{false, true} {
				for _, asSpace := range []bool{false, true} {
					if f := skelFold(x, asSpace, protoFirst); !seen[f] {
						seen[f] = true
						out = append(out, f)
					}
				}
			}
		}
	}
	return out
}

func dropMark(r rune) rune {
	if unicode.Is(unicode.M, r) {
		return -1
	}
	return r
}

func skelWindows(s string) []string {
	rs := []rune(s)
	if len(rs) <= skelWindow {
		return []string{s}
	}
	var ws []string
	for i := 0; ; i += skelWindow - skelOverlap {
		end := i + skelWindow
		if end >= len(rs) {
			return append(ws, string(rs[i:]))
		}
		ws = append(ws, string(rs[i:end]))
	}
}

// FoldPattern returns a regular expression matching lit, in any case, in
// any of CheckFolds' folds: each character becomes the alternation of
// its folds, upper and lower case, prototype after or before case
// folding (so I becomes i or l, and m becomes rn), and a space one or
// more spaces. The checks build their fixed patterns with it, since a
// pattern on the raw text misses the fold's own changes (0 folds to o).
func FoldPattern(lit string) string {
	var b strings.Builder
	for _, c := range lit {
		if c == ' ' {
			b.WriteString(" +")
			continue
		}
		set := map[string]bool{}
		for _, x := range []string{string(c), strings.ToUpper(string(c)), strings.ToLower(string(c))} {
			for _, protoFirst := range []bool{false, true} {
				if f := skelFold(x, false, protoFirst); f != "" && f != " " {
					set[regexp.QuoteMeta(f)] = true
				}
			}
		}
		alts := make([]string, 0, len(set))
		for f := range set {
			alts = append(alts, f)
		}
		sort.Strings(alts)
		b.WriteString("(?:" + strings.Join(alts, "|") + ")")
	}
	return b.String()
}
