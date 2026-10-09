package recall

import (
	_ "embed"
	"math"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

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
	secretKV   = regexp.MustCompile(`(?i)\b((?:pass(?:word|wd|code|phrase)?|pwd|pin|secret|client[_-]?secret|api[_-]?key|access[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|session(?:[_-]?id)?|cookie|recovery[_ -]?codes?|backup[_ -]?codes?|totp|2fa[_ -]?seed|seed)\b[ \t]*(?:is|[:=])[ \t]*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)`)
	otpauthURI = regexp.MustCompile(`(?i)otpauth://\S+`)
	urlRe      = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s<>"']+`)
	emailRe    = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	// Identifier shapes that are public by design: UPS tracking numbers.
	nonSecretID = regexp.MustCompile(`^1Z[0-9A-Z]{16}$`)
	// Grouped codes such as XXXXX-XXXXX-XXXXX (recovery and backup codes).
	groupedCode = regexp.MustCompile(`\b[A-Za-z0-9]{4,8}(?:-[A-Za-z0-9]{4,8}){2,}\b`)
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
	if !credPredicate.MatchString(credWords(f.Predicate)) {
		obj = sc.Scrub(f.Object)
	}
	return Fact{sc.Scrub(f.Subject), sc.Scrub(f.Predicate), obj}
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

// Scrub returns s with credential material replaced by Removed.
func (sc *Scrubber) Scrub(s string) string {
	if s == "" {
		return s
	}
	if sc != nil && sc.vault != nil {
		s = sc.vault(s)
	}
	s = pemBlock.ReplaceAllString(s, Removed)
	s = otpauthURI.ReplaceAllString(s, Removed)
	s = authHeader.ReplaceAllString(s, "${1} "+Removed)
	s = authScheme.ReplaceAllString(s, "${1} "+Removed)
	s = secretKV.ReplaceAllString(s, "${1}"+Removed)
	s = urlRe.ReplaceAllStringFunc(s, scrubURL)
	s = groupedCode.ReplaceAllStringFunc(s, func(m string) string {
		if (hasDigit(m) && hasLetter(m)) || evenGroups(m) {
			return Removed
		}
		return m
	})
	return scrubRandom(s)
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

// evenGroups reports whether every dash-separated group of m has the same
// length. Generated codes are cut evenly (XXXXX-XXXXX-...) whatever their
// alphabet, so a code of letters only or digits only is still removed, at
// any entropy; hyphenated words and dates have parts of differing length.
func evenGroups(m string) bool {
	gs := strings.Split(m, "-")
	for _, g := range gs[1:] {
		if len(g) != len(gs[0]) {
			return false
		}
	}
	return true
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
