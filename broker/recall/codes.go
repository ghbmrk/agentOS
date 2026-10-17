package recall

import (
	"regexp"
	"strings"
)

// Recovery and backup code shapes beyond the dash-joined even groups
// (RECALL-canary-3; ASSUMPTIONS R12): a keyed list of codes in any layout,
// groups joined by '.', '_' or any Unicode dash, groups of 3 or of 9 to 16, an
// uneven last group, two-group codes, look-alike characters, and a code split
// across fact fields.

var (
	// codeKey is a recovery or backup code key and, when present, its explicit
	// separator (":", "=", "is", "are").
	codeKey = regexp.MustCompile(`(?i)\b(?:recovery|backup)[ _-]?code(?:s\b|\(s\)|\b)((?:[ \t]*(?:(?:is|are)\b[ \t]*)?[:=])|[ \t]+(?:is|are)\b)?`)
	// codeKeyTail is a field that ends with a code key.
	codeKeyTail = regexp.MustCompile(`(?i)\b(?:recovery|backup)[ _-]?code(?:s|\(s\))?(?:[ \t]*(?:(?:is|are)\b[ \t]*)?[:=]?|[ \t]+(?:is|are))[ \t]*$`)
	// codeRun is a run of letter-digit groups joined by '-', '.' or '_'.
	codeRun   = regexp.MustCompile(`[A-Za-z0-9]+(?:[-._][A-Za-z0-9]+)+`)
	codeToken = regexp.MustCompile(`^[A-Za-z0-9]+(?:[-._][A-Za-z0-9]+)*$`)
	listMark  = regexp.MustCompile(`^(?:[-*•]|[0-9]{1,2}[.)])$`)
)

// fold maps what can hide a code's characters to ASCII: zero-width and soft
// hyphen characters are dropped, Unicode spaces become ' ', Unicode dashes
// '-', fullwidth forms and mathematical letters and digits their ASCII
// letters, and a token wholly of Latin look-alikes (Cyrillic, Greek) its
// Latin spelling. It is not full NFKC (x/text is not vendored; R12).
func fold(s string) string {
	i := 0
	for i < len(s) && s[i] < 0x80 {
		i++
	}
	if i == len(s) {
		return s
	}
	s = strings.Map(foldRune, s)
	var b strings.Builder
	last := 0
	for start := 0; start < len(s); {
		end := start
		for end < len(s) && !isSpace(s[end]) {
			end++
		}
		if t, ok := latinOf(s[start:end]); ok && t != s[start:end] {
			b.WriteString(s[last:start])
			b.WriteString(t)
			last = end
		}
		for end < len(s) && isSpace(s[end]) {
			end++
		}
		start = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func foldRune(r rune) rune {
	switch {
	case r == 0xAD, r >= 0x200B && r <= 0x200D, r == 0x2060, r == 0xFEFF:
		return -1
	case r == 0xA0, r == 0x1680, r >= 0x2000 && r <= 0x200A, r == 0x202F, r == 0x205F, r == 0x3000:
		return ' '
	case r >= 0x2010 && r <= 0x2015, r == 0x2043, r == 0x2212, r == 0xFE58, r == 0xFE63:
		return '-'
	case r >= 0xFF01 && r <= 0xFF5E:
		return r - 0xFEE0
	case r >= 0x1D400 && r <= 0x1D6A3:
		if k := (r - 0x1D400) % 52; k < 26 {
			return 'A' + k
		} else {
			return 'a' + k - 26
		}
	case r >= 0x1D7CE && r <= 0x1D7FF:
		return '0' + (r-0x1D7CE)%10
	}
	return r
}

// latinLike maps Cyrillic and Greek letters to the Latin letters they look like.
var latinLike = map[rune]byte{
	'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K', 'М': 'M',
	'О': 'O', 'Р': 'P', 'Ѕ': 'S', 'Т': 'T', 'Х': 'X', 'Ү': 'Y',
	'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i', 'ѕ': 's',
	'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N',
	'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X', 'ο': 'o',
}

// latinOf spells t in ASCII when every non-ASCII rune in it has a Latin
// look-alike.
func latinOf(t string) (string, bool) {
	b := make([]byte, 0, len(t))
	for _, r := range t {
		switch c, ok := latinLike[r]; {
		case r < 0x80:
			b = append(b, byte(r))
		case ok:
			b = append(b, c)
		default:
			return "", false
		}
	}
	return string(b), true
}

// scrubKeyedCodes removes the codes listed after a recovery or backup code
// key: one or more tokens, on one line or as a list, joined by spaces,
// commas, semicolons or list marks, up to the first token that is not a code
// or a blank line. A token is a code when it holds a digit or is 4 or more
// capitals; after an explicit key (a ':', '=', "is", "are" or a line break)
// the first token is a code whatever it is, and so is a one-case token of
// the length of the code before it or after it. Prose after a key without a
// separator ("backup codes for 2025") is kept.
func scrubKeyedCodes(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range codeKey.FindAllStringSubmatchIndex(s, -1) {
		if m[0] < last {
			continue
		}
		p := m[1]
		explicit := m[2] >= 0
		if !explicit {
			q := p
			for q < len(s) && (s[q] == ' ' || s[q] == '\t' || s[q] == '\r') {
				q++
			}
			explicit = q < len(s) && s[q] == '\n'
		}
		start, end := keyedRun(s, p, explicit)
		if end < 0 {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(Removed)
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

type keyedTok struct {
	start, end int // the item, list mark included, and the code's end
	core       string
	stop       bool // trailing punctuation ended the sentence
}

// keyedRun returns the span of the codes listed from p, or end -1.
func keyedRun(s string, p int, explicit bool) (int, int) {
	var toks []keyedTok
	item := -1
	for p < len(s) {
		nl := 0
		for p < len(s) && strings.IndexByte(" \t\r\n,;", s[p]) >= 0 {
			if s[p] == '\n' {
				nl++
			}
			p++
		}
		if nl >= 2 || p == len(s) {
			break
		}
		if item < 0 {
			item = p
		}
		if strings.HasPrefix(s[p:], Removed) {
			toks = append(toks, keyedTok{start: item, end: p + len(Removed), core: Removed})
			p += len(Removed)
			item = -1
			continue
		}
		q := p
		for q < len(s) && strings.IndexByte(" \t\r\n,;", s[q]) < 0 {
			q++
		}
		tok := s[p:q]
		if listMark.MatchString(tok) {
			p = q
			continue
		}
		core := strings.TrimLeft(tok, "(")
		lead := len(tok) - len(core)
		core = strings.TrimRight(core, ".:)!?")
		if len(core) < 3 || !codeToken.MatchString(core) {
			break
		}
		toks = append(toks, keyedTok{start: item, end: p + lead + len(core), core: core, stop: p+lead+len(core) < q})
		p = q
		item = -1
	}
	n := 0
	prev := 0
	for n < len(toks) {
		t := toks[n]
		ok := false
		switch {
		case t.core == Removed:
			ok = true
		case hasDigit(t.core) || len(t.core) >= 4 && asciiLetters(t.core) && strings.ToUpper(t.core) == t.core:
			ok = true
		case !explicit:
		case n == 0:
			ok = true
		case oneCase(t.core) && (len(t.core) == prev || prev == 0 && n+1 < len(toks) && len(toks[n+1].core) == len(t.core) && oneCase(toks[n+1].core)):
			ok = true
		}
		if !ok {
			break
		}
		if t.core != Removed {
			prev = len(t.core)
		}
		n++
		if t.stop {
			break
		}
	}
	if n == 0 || n == 1 && toks[0].core == Removed {
		return 0, -1
	}
	return toks[0].start, toks[n-1].end
}

// oneCase reports whether t's letters are all capitals or all small letters.
func oneCase(t string) bool {
	return t == strings.ToUpper(t) || t == strings.ToLower(t)
}

// scrubGroupedCodes replaces each run of groups joined by one of '-', '.' or
// '_' that codeLike accepts, taking the longest such run from each group.
func scrubGroupedCodes(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range codeRun.FindAllStringIndex(s, -1) {
		run := s[m[0]:m[1]]
		out := scrubRun(run)
		if out == run {
			continue
		}
		b.WriteString(s[last:m[0]])
		b.WriteString(out)
		last = m[1]
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func scrubRun(run string) string {
	gs := strings.FieldsFunc(run, func(r rune) bool { return r == '-' || r == '.' || r == '_' })
	var seps []byte
	for i := 0; i < len(run); i++ {
		if c := run[i]; c == '-' || c == '.' || c == '_' {
			seps = append(seps, c)
		}
	}
	var b strings.Builder
	for i := 0; i < len(gs); {
		j := len(gs)
		for ; j >= i+2; j-- {
			if same(seps[i:j-1]) && codeLike(gs[i:j], seps[i]) {
				break
			}
		}
		if j >= i+2 {
			b.WriteString(Removed)
		} else {
			b.WriteString(gs[i])
			j = i + 1
		}
		if j < len(gs) {
			b.WriteByte(seps[j-1])
		}
		i = j
	}
	return b.String()
}

func same(seps []byte) bool {
	for _, c := range seps {
		if c != seps[0] {
			return false
		}
	}
	return true
}

// codeLike reports whether groups joined by sep are a generated code:
//   - two groups: dash-joined, of 5 or more, each with a digit, with a letter
//     somewhere (GitHub's xxxxx-xxxxx);
//   - three or more groups, each mixing letters and digits;
//   - even groups of 3: four or more, mixed, or digits joined by dashes;
//   - even groups of 4 to 16: dash-joined, or holding a digit, or 16 or more
//     letters unlike English (R11's floor);
//   - an uneven last group, shorter than the rest: mixed, or four or more
//     dash-joined digit groups;
//   - otherwise dash-joined groups of 4 to 8 mixing letters and digits.
//
// Dates, versions, addresses and phone numbers have short or uneven groups.
func codeLike(gs []string, sep byte) bool {
	n, l := len(gs), len(gs[0])
	dash := sep == '-'
	joined := strings.Join(gs, "")
	mixed := hasDigit(joined) && hasLetter(joined)
	even, unevenLast, sized := true, true, true
	for i, g := range gs {
		if len(g) > 16 {
			return false
		}
		if len(g) != l {
			even = false
			if i < n-1 || len(g) > l {
				unevenLast = false
			}
		}
		if len(g) < 4 || len(g) > 8 {
			sized = false
		}
	}
	if n == 2 {
		return dash && even && l >= 5 && hasDigit(gs[0]) && hasDigit(gs[1]) && hasLetter(joined)
	}
	allMixed := true
	for _, g := range gs {
		if len(g) < 3 || !hasDigit(g) || !hasLetter(g) {
			allMixed = false
		}
	}
	switch {
	case allMixed:
		return true
	case l < 3:
		return false
	case l == 3:
		return even && n >= 4 && (mixed || dash && !hasLetter(joined))
	case even:
		return dash || hasDigit(joined) || len(joined) >= 16 && asciiLetters(joined) && !wordLike(joined)
	case unevenLast:
		return mixed || dash && n >= 4 && !hasLetter(joined)
	}
	return dash && mixed && sized
}

// ScrubFacts scrubs each fact as ScrubFact does, and removes both parts of a
// code split across two fields of a fact or across the objects of
// consecutive facts, which no field shows whole (R12).
func (sc *Scrubber) ScrubFacts(fs []Fact) []Fact {
	out := make([]Fact, 0, len(fs))
	for _, f := range fs {
		out = append(out, sc.ScrubFact(f))
	}
	var drop []*string
	pair := func(a, b *string) {
		da, db := sc.splitCode(*a, *b)
		if da {
			drop = append(drop, a)
		}
		if db {
			drop = append(drop, b)
		}
	}
	for i := range out {
		f := &out[i]
		pair(&f.Subject, &f.Predicate)
		pair(&f.Predicate, &f.Object)
		pair(&f.Subject, &f.Object)
		if i > 0 {
			pair(&out[i-1].Object, &f.Object)
		}
	}
	for _, p := range drop {
		*p = Removed
	}
	return out
}

// splitCode reports which of a and b to remove when, read together, they
// are a code neither is alone: b after a field ending with a code key; or
// both, when a's last token and b's first are one-case code groups of one
// length that join with '-' into a grouped code, or both mix letters and
// digits and join into a random-looking token. Each field alone is already
// scrubbed, so a removal found here spans the join.
func (sc *Scrubber) splitCode(a, b string) (bool, bool) {
	if a == "" || b == "" || a == Removed || b == Removed {
		return false, false
	}
	n := strings.Count(sc.Scrub(a), Removed) + strings.Count(sc.Scrub(b), Removed)
	more := func(j string) bool { return strings.Count(sc.Scrub(a+j+b), Removed) > n }
	if codeKeyTail.MatchString(fold(a)) {
		return false, more(" ")
	}
	fa, fb := strings.Fields(fold(a)), strings.Fields(fold(b))
	if len(fa) == 0 || len(fb) == 0 {
		return false, false
	}
	ea, eb := fa[len(fa)-1], fb[0]
	if !codeToken.MatchString(ea) || !codeToken.MatchString(eb) || !oneCase(ea) || !oneCase(eb) {
		return false, false
	}
	if hasDigit(ea) && hasLetter(ea) && hasDigit(eb) && hasLetter(eb) && randomLooking(ea+eb) {
		return true, true
	}
	ga := strings.FieldsFunc(ea, func(r rune) bool { return r == '-' || r == '.' || r == '_' })
	gb := strings.FieldsFunc(eb, func(r rune) bool { return r == '-' || r == '.' || r == '_' })
	if len(ga[len(ga)-1]) == len(gb[0]) && strings.Contains(scrubGroupedCodes(ea+"-"+eb), Removed) {
		return true, true
	}
	return false, false
}
