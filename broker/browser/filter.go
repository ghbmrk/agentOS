package browser

import (
	"math"
	"regexp"
	"strings"
)

// Redacted replaces every value the filter removes; it matches the vault's
// placeholder so agents see one marker.
const Redacted = "[REDACTED]"

// MaxSnapshot bounds the snapshot text returned per request, in bytes.
const MaxSnapshot = 256 * 1024

// Scrubber removes known secret values (the vault's Redactor: exact values and
// their common encodings).
type Scrubber interface {
	Redact([]byte) []byte
}

// CRED-10's fixed-pattern detector, ported from S5's protocol.py so the broker
// applies it outside the driver.
var (
	tokenPatterns = []*regexp.Regexp{
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), // JWT
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}`),     // GitHub
		regexp.MustCompile(`\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}`),                           // API keys
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                                       // AWS
		regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),                             // Slack
	}
	// labelled: a run of 16 or more token characters right after a secret
	// label ("api key: 9f86...", "token 9f86...", "secret: wJal.../K7..."),
	// which the entropy rule misses for hex and for values with '/'. The value
	// must hold a digit, so labelled prose ("token-based-auth") is left alone.
	// Stricter than S5's protocol.py, which has no such rule.
	labelled    = regexp.MustCompile(`(?i)(api[\s_-]?key|key|token|secret|password|passwd)s?["']?(?:\s*\[ref=(?:f[0-9]+)?e[0-9]+\])?\s*(?:[:=]\s*)?["']?([A-Za-z0-9+/=_.-]{16,})`)
	secretParam = regexp.MustCompile(`(?i)(token|code|key|sig|auth|session|password|secret)`)
	candidate   = regexp.MustCompile(`[A-Za-z0-9+_=-]{24,}`)
	urlInText   = regexp.MustCompile(`https?://[^\s"'<>]+|/url: \S+`)
	lower       = regexp.MustCompile(`[a-z]`)
	upper       = regexp.MustCompile(`[A-Z]`)
	digit       = regexp.MustCompile(`[0-9]`)
)

// Detect returns text with known token formats, secret-named URL parameters
// and high-entropy runs replaced by Redacted, and the number of replacements.
func Detect(text string) (string, int) {
	n := 0
	text = urlInText.ReplaceAllStringFunc(text, func(m string) string {
		prefix := ""
		if strings.HasPrefix(m, "/url: ") {
			prefix, m = "/url: ", m[len("/url: "):]
		}
		out, k := redactURL(m)
		n += k
		return prefix + out
	})
	text = redactLabelled(text, &n)
	for _, p := range tokenPatterns {
		text = p.ReplaceAllStringFunc(text, func(string) string { n++; return Redacted })
	}
	text = candidate.ReplaceAllStringFunc(text, func(m string) string {
		if highEntropy(m) {
			n++
			return Redacted
		}
		return m
	})
	return text, n
}

func redactLabelled(text string, n *int) string {
	var b strings.Builder
	last := 0
	for _, m := range labelled.FindAllStringSubmatchIndex(text, -1) {
		v0, v1 := m[4], m[5]
		if !digit.MatchString(text[v0:v1]) {
			continue
		}
		b.WriteString(text[last:v0])
		b.WriteString(Redacted)
		last = v1
		*n++
	}
	if last == 0 {
		return text
	}
	return b.String() + text[last:]
}

// redactURL drops the values of secret-named query and fragment parameters,
// e.g. an OAuth implicit-flow '#access_token=...'.
func redactURL(u string) (string, int) {
	n := 0
	frag := ""
	if i := strings.IndexByte(u, '#'); i >= 0 {
		u, frag = u[:i], u[i+1:]
	}
	query := ""
	hasQuery := false
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u, query, hasQuery = u[:i], u[i+1:], true
	}
	var k int
	if hasQuery {
		query, k = redactPairs(query)
		n += k
		u += "?" + query
	}
	if frag != "" || strings.HasSuffix(u, "#") {
		if strings.Contains(frag, "=") {
			frag, k = redactPairs(frag)
			n += k
		}
	}
	if frag != "" {
		u += "#" + frag
	}
	return u, n
}

func redactPairs(s string) (string, int) {
	n := 0
	parts := strings.Split(s, "&")
	for i, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if ok && v != "" && secretParam.MatchString(k) {
			parts[i] = k + "=" + Redacted
			n++
		}
	}
	return strings.Join(parts, "&"), n
}

// highEntropy: mixed character classes and at least 4 bits per character, so
// random tokens match and words or paths do not.
func highEntropy(s string) bool {
	if len(s) < 24 {
		return false
	}
	classes := 0
	for _, re := range []*regexp.Regexp{lower, upper, digit} {
		if re.MatchString(s) {
			classes++
		}
	}
	if classes < 2 {
		return false
	}
	counts := map[rune]float64{}
	for _, c := range s {
		counts[c]++
	}
	h, l := 0.0, float64(len(s))
	for _, c := range counts {
		h -= c / l * math.Log2(c/l)
	}
	return h >= 4.0
}

// filter applies the vault's exact values first, then the detector.
type filter struct{ scrub Scrubber }

func (f filter) text(s string) (string, int) {
	n := 0
	if f.scrub != nil {
		before := strings.Count(s, Redacted)
		s = string(f.scrub.Redact([]byte(s)))
		if d := strings.Count(s, Redacted) - before; d > 0 {
			n += d
		}
	}
	s, k := Detect(s)
	return s, n + k
}
