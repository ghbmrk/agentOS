package recall

import (
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
	// Shapes a page or a tool result can carry that are credentials even
	// when they are not high-entropy (CRED-10; the S5 spike's token list).
	knownTokens = regexp.MustCompile(`` +
		`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}` +
		`|\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}` +
		`|\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}` +
		`|\bAKIA[0-9A-Z]{16}\b` +
		`|\bxox[abprs]-[A-Za-z0-9-]{10,}`)
)

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
	s = knownTokens.ReplaceAllString(s, Removed)
	s = urlRe.ReplaceAllStringFunc(s, scrubURL)
	s = groupedCode.ReplaceAllStringFunc(s, func(m string) string {
		if hasDigit(m) && hasLetter(m) {
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

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// randomLooking: at least 16 characters mixing letters and digits with high
// per-character entropy, or at least 20 characters of very high entropy.
// Email addresses are kept.
func randomLooking(t string) bool {
	if len(t) < 16 || emailRe.MatchString(t) || nonSecretID.MatchString(t) {
		return false
	}
	h := entropy(t)
	if hasDigit(t) && hasLetter(t) && h >= 3.0 {
		return true
	}
	return len(t) >= 20 && h >= 3.5
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
