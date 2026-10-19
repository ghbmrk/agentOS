package recall

import (
	_ "embed"
	"math"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// secretKVBody is a credential key, its separator and its value.
const secretKVBody = `((?:pass(?:word|wd|code|phrase)?|pwd|pin|secret|client[_-]?secret|api[_-]?key|access[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session(?:[_-]?id)?|cookie|recovery[_ -]?codes?|backup[_ -]?codes?|totp|2fa[_ -]?seed|seed)\b[ \t]*(?:is|[:=])[ \t]*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`

// secretKVKeys holds the small spelling each key secretKVBody names starts
// with; TestSecretKVMatchesFindAll holds the two to the same keys.
var secretKVKeys = []string{"pass", "pwd", "pin", "secret", "client", "api", "access", "refresh", "id", "session", "cookie", "recovery", "backup", "totp", "2fa", "seed"}

// Removed replaces every value the scrubber takes out.
const Removed = "[credential removed]"

// Scrubber removes reusable authentication material from text before the
// index or the event bus stores it (CRED-1: no such material in the recall
// index, in storage, or in I/O readable by a model-directed process). It is
// pattern-based and fails toward removing too much: a long random-looking
// identifier is removed even when it is harmless. The vault's own redactor
// (CRED-7), when supplied, runs first and catches values the vault holds in
// any of their encodings.
type Scrubber struct {
	vault func(string) string
}

// NewScrubber returns a scrubber. vault may be nil.
func NewScrubber(vault func(string) string) *Scrubber { return &Scrubber{vault: vault} }

var (
	pemBlock   = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|\z)`)
	authHeader = regexp.MustCompile(`(?im)^([ \t]*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token)[ \t]*:)[^\r\n]*`)
	authScheme = regexp.MustCompile(`(?i)\b(bearer|basic|token|digest)\s+[A-Za-z0-9._~+/=-]{8,}`)
	secretKV   = regexp.MustCompile(`(?i)\b` + secretKVBody)
	// secretKVAt is secretKV at the start of the text, without its \b, which
	// secretKVMatches checks with the rune before.
	secretKVAt = regexp.MustCompile(`(?i)^` + secretKVBody)
	otpauthURI = regexp.MustCompile(`(?i)otpauth://\S+`)
	urlRe      = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s<>"']+`)
	emailRe    = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	// Identifier shapes that are public by design: UPS tracking numbers.
	nonSecretID = regexp.MustCompile(`^1Z[0-9A-Z]{16}$`)
	// Shapes a page or a tool result can carry that are credentials even
	// when they are not high-entropy (CRED-10; the S5 spike's token list).
	knownTokens = regexp.MustCompile(`` +
		`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}` +
		`|\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}` +
		`|\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}` +
		`|\bAKIA[0-9A-Z]{16}\b` +
		`|\bxox[abprs]-[A-Za-z0-9-]{10,}`)
	// Fact predicates naming credential material, matched on whole words of
	// the predicate as credWords spells it (api_key, recovery_codes, 2_fa_seed),
	// or with key(s) as any word but the first, or as the whole name before a
	// version or number (ssh_key_backup, key_v_2; key_points is kept).
	credPredicate = regexp.MustCompile(`(?:^|_)(?:pass(?:word|wd|code|phrase)?s?|pwds?|pins?|secrets?|credentials?|(?:api|access|private|secret|signing)_?keys?|tokens?|recovery|backup_?codes?|seeds?|mnemonic|totps?|otps?|2_?fa|mfa|cookies?|passkeys?|pws?|security_answers?)(?:_|$)|_keys?(?:_|$)|^keys?(?:_v)?(?:_\d+)?$`)
)

// ScrubFact scrubs a fact. When its predicate names credential material the
// object is removed whole, since it may look harmless on its own (CRED-1).
func (sc *Scrubber) ScrubFact(f Fact) Fact {
	obj := Removed
	if !credPredicateMatch(f.Predicate) {
		obj = sc.Scrub(f.Object)
	}
	return Fact{sc.Scrub(f.Subject), sc.Scrub(f.Predicate), obj}
}

// credPredicateMatch reports whether a predicate names credential material.
// fold writes the long s small and the Kelvin sign capital, but either can
// stand for a letter of the other case ("toKen", "ſECRET"), and the case
// decides where credWords splits; so the predicate is also read with each
// of them in the case of the ASCII letter beside it (#2357).
func credPredicateMatch(p string) bool {
	return credPredicate.MatchString(credWords(fold(p))) ||
		strings.ContainsAny(p, "\u017f\u212a") && credPredicate.MatchString(credWords(fold(caseLikeNeighbour(p))))
}

// caseLikeNeighbour writes each long s and Kelvin sign in p as the ASCII s
// or k, in the case of the ASCII letter before it, or else of the first
// ASCII letter after it; with neither, small.
func caseLikeNeighbour(p string) string {
	rs := []rune(p)
	upper := func(r rune) bool { return r >= 'A' && r <= 'Z' }
	letter := func(r rune) bool { return upper(r) || r >= 'a' && r <= 'z' }
	for i, r := range rs {
		if r != '\u017f' && r != '\u212a' {
			continue
		}
		c := 's'
		if r == '\u212a' {
			c = 'k'
		}
		switch {
		case i > 0 && letter(rs[i-1]):
			if upper(rs[i-1]) {
				c -= 'a' - 'A'
			}
		default:
			j := i + 1
			for j < len(rs) && (rs[j] == '\u017f' || rs[j] == '\u212a') {
				j++
			}
			if j < len(rs) && upper(rs[j]) {
				c -= 'a' - 'A'
			}
		}
		rs[i] = c
	}
	return string(rs)
}

// credWords spells a predicate as lower-case words joined by '_', splitting
// at case boundaries, between letters and digits either way, and at anything
// but letters and digits: "recoveryCodes", "API-Key", "2FA seed", "PINs",
// "password1" and "v2password" become recovery_codes, api_key, 2_fa_seed,
// pins, password_1 and v_2_password.
func credWords(p string) string {
	var b []byte
	sep := func() {
		if len(b) > 0 && b[len(b)-1] != '_' {
			b = append(b, '_')
		}
	}
	lower := func(i int) bool { return i < len(p) && p[i] >= 'a' && p[i] <= 'z' }
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c >= 'A' && c <= 'Z':
			// An acronym's plural s ("OTPs") stays on the acronym.
			plural := i > 0 && p[i-1] >= 'A' && p[i-1] <= 'Z' && p[i+1:] != "" && p[i+1] == 's' && !lower(i+2)
			if i > 0 && caseBoundary(p, i) && !plural {
				sep()
			}
			b = append(b, c|0x20)
		case c >= 'a' && c <= 'z':
			if len(b) > 0 && b[len(b)-1] >= '0' && b[len(b)-1] <= '9' {
				sep()
			}
			b = append(b, c)
		case c >= '0' && c <= '9':
			if len(b) > 0 && b[len(b)-1] >= 'a' && b[len(b)-1] <= 'z' {
				sep()
			}
			b = append(b, c)
		default:
			sep()
		}
	}
	return string(b)
}

// tokenParam reports whether a URL query key names a credential (REV-5's
// fixed patterns: token, code, key, sig, auth; plus session and password).
func tokenParam(k string) bool {
	k = strings.ToLower(k)
	for _, p := range []string{"token", "code", "key", "sig", "auth", "session", "pass", "secret", "otp"} {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

// Scrub returns s with credential material replaced by Removed. It scrubs
// the word-anchored shapes as written, then everything as fold spells it,
// keeping the folded spelling only when that pass removes more: folding a
// look-alike next to a token or key joins the two and hides the word boundary
// the written text had.
func (sc *Scrubber) Scrub(s string) string {
	if s == "" {
		return s
	}
	if sc != nil && sc.vault != nil {
		s = sc.vault(s)
	}
	s = scrubAnchored(s)
	f := fold(s)
	if out := scrubText(f); out != f {
		return out
	}
	return s
}

func scrubText(s string) string {
	s = scrubAnchored(s)
	if anchoredGates[gateKeyedCodes](s, caseSkeleton(s)) {
		s = scrubKeyedCodes(s)
	}
	if anchoredGates[gateGroupedCodes](s, "") {
		s = scrubGroupedCodes(s)
	}
	return scrubRandom(s)
}

// scrubAnchored removes the shapes found by a key, scheme or prefix. Each
// leaves Removed as it is, so running it again changes nothing.
//
// Each pattern runs only when the text holds a literal every match of it
// must hold (anchoredGates), so the common text that holds none skips the
// regexp engine: Scrub runs on every field of every fact and message, and
// seven backtracking scans per pass made a 20,000-case test outrun CI's
// 10-minute limit under -race (#2228). The gates only skip a pattern that
// cannot match; TestAnchoredGatesNeverSkipAMatch holds them to that.
func scrubAnchored(s string) string {
	sk := caseSkeleton(s)
	run := func(i int, f func(string) string) {
		if anchoredGates[i](s, sk) {
			if out := f(s); out != s {
				s, sk = out, caseSkeleton(out)
			}
		}
	}
	run(gatePEM, func(s string) string { return pemBlock.ReplaceAllString(s, Removed) })
	run(gateOTPAuth, func(s string) string { return otpauthURI.ReplaceAllString(s, Removed) })
	run(gateAuthHeader, func(s string) string { return authHeader.ReplaceAllString(s, "${1} "+Removed) })
	run(gateAuthScheme, func(s string) string { return authScheme.ReplaceAllString(s, "${1} "+Removed) })
	run(gateSecretKV, scrubSecretKV)
	run(gateKnownTokens, scrubKnownTokens)
	run(gateURL, func(s string) string { return urlRe.ReplaceAllStringFunc(s, scrubURL) })
	return s
}

const (
	gatePEM = iota
	gateOTPAuth
	gateAuthHeader
	gateAuthScheme
	gateSecretKV
	gateKnownTokens
	gateURL
	gateKeyedCodes   // codeKey, in scrubText
	gateGroupedCodes // codeRun, in scrubText
)

// anchoredGates[i](s, caseSkeleton(s)) is false only when the pattern gate i
// guards cannot match s (the last two guard scrubText's code patterns). A
// case-insensitive pattern's literal is looked up in the skeleton, so its
// Unicode case variants (the Kelvin sign for k, the long s for s) still open
// the gate.
var anchoredGates = [...]func(s, sk string) bool{
	gatePEM:     func(s, _ string) bool { return strings.Contains(s, "-----BEGIN ") },
	gateOTPAuth: func(s, sk string) bool { return strings.Contains(sk, "otpauth://") },
	gateAuthHeader: func(s, sk string) bool {
		return strings.IndexByte(s, ':') >= 0 && mayHold(sk, "authorization", "cookie", "api-key", "x-auth-token")
	},
	gateAuthScheme: func(_, sk string) bool { return mayHold(sk, "bearer", "basic", "token", "digest") },
	// Every key secretKV names holds one of these words; client_secret,
	// refresh_token and id_token hold secret or token.
	gateSecretKV: func(s, sk string) bool {
		return (strings.ContainsAny(s, ":=") || strings.Contains(sk, "is")) &&
			mayHold(sk, "pass", "pwd", "pin", "secret", "api", "access", "token", "session", "cookie", "recovery", "backup", "totp", "2fa", "seed")
	},
	// knownTokens is case-sensitive; every ghX_ prefix starts gh.
	gateKnownTokens:  func(s, _ string) bool { return mayHold(s, "eyJ", "gh", "github_pat_", "sk-", "AKIA", "xox") },
	gateURL:          func(s, _ string) bool { return strings.Contains(s, "://") },
	gateKeyedCodes:   func(_, sk string) bool { return mayHold(sk, "recovery", "backup") },
	gateGroupedCodes: func(s, _ string) bool { return strings.ContainsAny(s, "-._") },
}

func mayHold(s string, words ...string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// caseSkeleton spells s one byte per rune: the small ASCII letter a (?i)
// pattern's letter would match the rune as (K, the Kelvin sign and k all
// become k; S, the long s and s become s), any other ASCII byte as itself,
// and any other rune as 0. A (?i) pattern's ASCII literal matches s only
// where its small spelling appears in the skeleton.
func caseSkeleton(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToLower(s)
	}
	b := make([]byte, 0, len(s))
	for _, r := range s {
		b = append(b, skeletonByte(r))
	}
	return string(b)
}

func skeletonByte(r rune) byte {
	switch {
	case r >= 'A' && r <= 'Z':
		return byte(r + 'a' - 'A')
	case r < 0x80:
		return byte(r)
	// The only other runes whose case-fold orbit holds an ASCII letter
	// (TestSkeletonMatchesFoldOrbits checks every rune).
	case r == '\u212a': // Kelvin sign
		return 'k'
	case r == '\u017f': // long s
		return 's'
	}
	return 0
}

// scrubSecretKV replaces each keyed value with Removed, leaving a value that
// is already Removed as it is, so a second pass does not mangle the marker.
func scrubSecretKV(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range secretKVMatches(s) {
		if strings.HasPrefix(s[m[4]:], Removed) {
			continue
		}
		b.WriteString(s[last:m[4]])
		b.WriteString(Removed)
		last = m[1]
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// secretKVMatches returns what secretKV.FindAllStringSubmatchIndex(s, -1)
// does, in time linear in s. Rather than try the pattern's whole key
// alternation at every byte, it walks s once and tries secretKVAt only at a
// word boundary (\b, as regexp reads it) where the skeleton spells the
// start of a key; every match starts at such a place. A try reads from its
// key no further than its match, or the byte that rules a match out, and
// the walk resumes after a match, as FindAll does.
func secretKVMatches(s string) [][]int {
	var out [][]int
	prevWord := false
	for c := 0; c < len(s); {
		r, n := utf8.DecodeRuneInString(s[c:])
		word := isWordRune(r)
		if word != prevWord && keyStartsAt(s[c:]) {
			if m := secretKVAt.FindStringSubmatchIndex(s[c:]); m != nil {
				for i := range m {
					if m[i] >= 0 {
						m[i] += c
					}
				}
				out = append(out, m)
				c = m[1]
				last, _ := utf8.DecodeLastRuneInString(s[:c])
				prevWord = isWordRune(last)
				continue
			}
		}
		prevWord = word
		c += n
	}
	return out
}

// isWordRune is regexp's \w for \b: ASCII letters, digits and '_'.
func isWordRune(r rune) bool {
	return r == '_' || r >= '0' && r <= '9' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z'
}

// keyStartsAt reports whether s starts with a secretKVKeys word as the
// skeleton spells it.
func keyStartsAt(s string) bool {
	var buf [8]byte
	k := 0
	for _, r := range s {
		if k == len(buf) {
			break
		}
		buf[k] = skeletonByte(r)
		k++
	}
	for _, w := range secretKVKeys {
		if k >= len(w) && string(buf[:len(w)]) == w {
			return true
		}
	}
	return false
}

// scrubKnownTokens replaces each known token shape together with the
// dash-, underscore- or alphanumeric run it starts inside: a shape such as
// xoxs- can begin at a later group of a grouped code, and replacing only
// from there would keep the code's leading groups (#1844). The run takes in
// the long s and the Kelvin sign too: the shapes' ASCII classes stop at
// them, and once folded the tail behind them reads as too short to look
// random, so "ghp_…ſ…" kept its tail (#2357).
func scrubKnownTokens(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range knownTokens.FindAllStringIndex(s, -1) {
		if m[0] >= last {
			start := m[0]
			for start > last && tokenRuneBefore(s[:start]) > 0 {
				start -= tokenRuneBefore(s[:start])
			}
			b.WriteString(s[last:start])
			b.WriteString(Removed)
		}
		// A shape found inside the run already replaced extends it.
		last = max(last, m[1])
		for last < len(s) && tokenRuneAt(s[last:]) > 0 {
			last += tokenRuneAt(s[last:])
		}
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// tokenRuneAt and tokenRuneBefore give the length of the token byte, long s
// or Kelvin sign at the start or the end of s, or 0.
func tokenRuneAt(s string) int {
	if s != "" && isTokenByte(s[0]) {
		return 1
	}
	return tokenCaseRune(utf8.DecodeRuneInString(s))
}

func tokenRuneBefore(s string) int {
	if s != "" && isTokenByte(s[len(s)-1]) {
		return 1
	}
	return tokenCaseRune(utf8.DecodeLastRuneInString(s))
}

func tokenCaseRune(r rune, n int) int {
	if r == '\u017f' || r == '\u212a' {
		return n
	}
	return 0
}

func isTokenByte(c byte) bool {
	return c == '-' || c == '_' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// scrubURL drops userinfo, credential-named query values, the fragment when
// it carries parameters, and random-looking path segments.
func scrubURL(raw string) string {
	// Drop userinfo textually first: an unescaped password can hold '?',
	// '#' or '@', which would otherwise move it into the host, query or
	// fragment. The authority ends at the first '/' after the scheme.
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		end := strings.IndexByte(rest, '/')
		if end < 0 {
			end = len(rest)
		}
		if at := strings.LastIndexByte(rest[:end], '@'); at >= 0 {
			raw = raw[:i+3] + rest[at+1:]
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Removed
	}
	if u.User != nil {
		u.User = nil
	}
	if u.RawQuery != "" {
		q := u.Query()
		for k, vs := range q {
			if tokenParam(k) {
				q[k] = []string{"REMOVED"}
				continue
			}
			for i, v := range vs {
				if randomLooking(v) {
					vs[i] = "REMOVED"
				}
			}
		}
		u.RawQuery = q.Encode()
	}
	if strings.ContainsAny(u.Fragment, "=&") {
		u.Fragment = "REMOVED"
	}
	segs := strings.Split(u.Path, "/")
	for i, seg := range segs {
		if randomLooking(seg) {
			segs[i] = "REMOVED"
		}
	}
	u.Path = strings.Join(segs, "/")
	u.RawPath = ""
	return u.String()
}

// scrubRandom replaces whitespace-delimited tokens that look like random
// secrets (keys, tokens, cookies, seeds, generated passwords).
func scrubRandom(s string) string {
	var b strings.Builder
	i := 0
	for i < len(s) {
		j := i
		for j < len(s) && !isSpace(s[j]) {
			j++
		}
		if j > i {
			tok := s[i:j]
			core := strings.Trim(tok, "\"'()[]{}<>.,;:!?")
			if core != "" && !strings.Contains(core, "://") && !strings.Contains(core, Removed) && randomLooking(core) {
				k := strings.Index(tok, core)
				b.WriteString(tok[:k])
				b.WriteString(Removed)
				b.WriteString(tok[k+len(core):])
			} else {
				b.WriteString(tok)
			}
		}
		for j < len(s) && isSpace(s[j]) {
			b.WriteByte(s[j])
			j++
		}
		i = j
	}
	return b.String()
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// randomLooking: at least 16 characters mixing letters and digits with high
// per-character entropy; letters only (base32 padding aside) and unlike
// English (wordLike); or at least 20 other characters of very high entropy.
// Email addresses are kept.
func randomLooking(t string) bool {
	if len(t) < 16 || emailRe.MatchString(t) || nonSecretID.MatchString(t) {
		return false
	}
	if l := strings.TrimRight(t, "="); len(l) >= 16 && asciiLetters(l) {
		return !wordLike(l)
	}
	h := entropy(t)
	if hasDigit(t) && hasLetter(t) && h >= 3.0 {
		return true
	}
	return len(t) >= 20 && h >= 3.5
}

// letterModel holds letter bigram and trigram log-ratios against uniform
// letters, in 1/letterScale bits (letters_gen.go; ASSUMPTIONS R11).
//
//go:embed letters.bin
var letterModel []byte

const (
	letterScale = 8
	// wordFloor is the score, in model units, a letters-only token needs to
	// be kept: 24 bits, so a uniformly random one is kept with probability at
	// most 2^-24 at any length (TestLetterModelNormalized).
	wordFloor = 24 * letterScale
)

// wordLike reports whether an ASCII letters-only token scores at least
// wordFloor: the log-ratio of its likelihood under the English letter model
// to its likelihood as uniform random letters. Case boundaries
// (getUserName, XMLHttp) start a new word, scored afresh.
func wordLike(t string) bool {
	score, run := 0, 0
	var a, b int
	for i := 0; i < len(t); i++ {
		if i > 0 && caseBoundary(t, i) {
			run = 0
		}
		c := int(t[i]|0x20) - 'a'
		switch {
		case run == 1:
			score += int(int8(letterModel[b*26+c]))
		case run >= 2:
			score += int(int8(letterModel[26*26+(a*26+b)*26+c]))
		}
		a, b = b, c
		run++
	}
	return score >= wordFloor
}

// caseBoundary reports whether t[i] starts a word: a capital after a small
// letter, or a capital before a small letter after a capital (the H of XMLHttp).
func caseBoundary(t string, i int) bool {
	up := func(c byte) bool { return c >= 'A' && c <= 'Z' }
	if !up(t[i]) {
		return false
	}
	return !up(t[i-1]) || i+1 < len(t) && t[i+1] >= 'a' && t[i+1] <= 'z'
}

func asciiLetters(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i] | 0x20; c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

func entropy(t string) float64 {
	n := map[rune]int{}
	total := 0
	for _, r := range t {
		n[r]++
		total++
	}
	var h float64
	for _, c := range n {
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}

func hasDigit(s string) bool { return strings.IndexFunc(s, unicode.IsDigit) >= 0 }
func hasLetter(s string) bool {
	return strings.IndexFunc(s, unicode.IsLetter) >= 0
}
