// Package match is the one matcher of the core (KRN-12, CLK-4): CLK-4's
// fixed-pattern detector, moved here from broker/browser, which imports it
// back, and the decoy table's values and destinations added to it. It is a
// standard-library package, so the kernel can run it on its outbound path
// and the edge link can run it on what the core sends (DECOY-b, DECOY-c).
// The enforcer imports nothing from it: it trips on its own fixed addresses.
package match

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// Redacted replaces every value Detect removes; it matches the vault's
// placeholder so agents see one marker.
const Redacted = "[REDACTED]"

// CLK-4's (formerly CRED-10's) fixed-pattern detector, ported from S5's protocol.py so the broker
// applies it outside the driver.
var (
	tokenPatterns = []*regexp.Regexp{
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), // JWT
		regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}`),     // GitHub
		regexp.MustCompile(`\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}`),                           // API keys
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),                                       // AWS
		regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),                             // Slack
	}
	// labelled: a run of 16 or more token characters after a secret label
	// ("api key: 9f86...", "token 9f86...", "secret: wJal.../K7..."), which
	// the entropy rule misses for hex and for values with '/'. The label must
	// stand alone ('_' counts as a break, for "aws_secret_access_key") and be
	// followed by a separator: whitespace, ':' or '=', or quotes and short
	// snapshot attribute groups ("[active] [ref=e5] [cursor=pointer]"). So
	// paths and file names such as "keyboard-shortcuts-v2", "turkey/..." or
	// "api_key_rotation_2026.pdf" stay intact. A second, case-sensitive branch
	// takes a capitalised label after any letter or digit, for camelCase
	// keys ("accessToken", "clientSecret", "myApiKey", "openAIKey",
	// "AWSSecret"), while all-caps words ("TURKEY", "MONKEYS") stay intact. The value must hold a digit,
	// so labelled prose ("token-based-auth") is left alone too.
	// Stricter than S5's protocol.py, which has no such rule.
	labelled = regexp.MustCompile(`(?i)(?:(?:^|[^a-z0-9])(?:api[\s_-]?key|key|token|secret|password|passwd)` +
		`|(?-i:[A-Za-z0-9](?:Api[\s_-]?[Kk]ey|Key|Token|Secret|Password|Passwd)))s?` +
		`(?:["']|\s*\[[^\]\n]{1,40}\])*(?:\s*[:=]\s*|\s+)["']?([A-Za-z0-9+/=_.-]{16,})`)
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
		v0, v1 := m[2], m[3]
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

// Pattern reports whether text holds anything Detect would redact.
func Pattern(text string) bool {
	_, n := Detect(text)
	return n > 0
}

// MaxValue bounds one table value, so a stream's carried tail stays small.
const MaxValue = 1 << 10

// carryPattern is how much of a stream's past bytes a write is scanned with
// for CLK-4's patterns, so a token split across two writes still matches.
const carryPattern = 4 << 10

// The IPv6 prefixes through which an IPv4 destination can be named: the
// well-known and local-use NAT64 prefixes (RFC 6052, RFC 8215), 6to4
// (RFC 3056) and Teredo (RFC 4380).
var (
	nat64      = netip.MustParsePrefix("64:ff9b::/96")
	nat64Local = netip.MustParsePrefix("64:ff9b:1::/48")
	sixToFour  = netip.MustParsePrefix("2002::/16")
	teredo     = netip.MustParsePrefix("2001::/32")
)

// Value is one table value and the ID a trip names it by.
type Value struct {
	ID    int
	Bytes []byte
}

// Matcher holds the table's values, in each of their common encodings, and
// its destinations. It is immutable, so one serves many streams.
type Matcher struct {
	forms []form
	dests map[netip.Addr]int
	carry int
}

type form struct {
	id int
	b  []byte
}

// New makes a matcher. A value is matched raw and in the encodings a sender
// most often wraps it in: JSON string, URL query, lower hex, standard and
// URL-safe base64. An empty value is skipped: a destination-only entry. dests
// maps an address to the ID a trip names it by.
func New(values []Value, dests map[netip.Addr]int) *Matcher {
	m := &Matcher{dests: map[netip.Addr]int{}}
	for _, v := range values {
		if len(v.Bytes) == 0 || len(v.Bytes) > MaxValue {
			continue
		}
		for _, f := range encodings(v.Bytes) {
			m.forms = append(m.forms, form{v.ID, f})
			m.carry = max(m.carry, len(f)-1)
		}
	}
	for a, id := range dests {
		m.dests[a.Unmap()] = id
	}
	return m
}

func encodings(v []byte) [][]byte {
	j, _ := json.Marshal(string(v))
	out := [][]byte{
		v,
		j[1 : len(j)-1],
		[]byte(url.QueryEscape(string(v))),
		[]byte(hex.EncodeToString(v)),
		[]byte(base64.StdEncoding.EncodeToString(v)),
		[]byte(base64.RawURLEncoding.EncodeToString(v)),
	}
	// The padded forms also match without their padding, as they appear
	// inside a longer encoded run.
	out = append(out, bytes.TrimRight(out[4], "="))
	var uniq [][]byte
	for _, f := range out {
		dup := false
		for _, u := range uniq {
			dup = dup || bytes.Equal(u, f)
		}
		if !dup {
			uniq = append(uniq, f)
		}
	}
	return uniq
}

// Dest returns the ID of the table destination a is, in any form Forms
// gives.
func (m *Matcher) Dest(a netip.Addr) (int, bool) {
	for _, f := range Forms(a) {
		if id, ok := m.dests[f]; ok {
			return id, true
		}
	}
	return 0, false
}

// Forms is a without its zone, and every IPv4 address it can carry a
// connection to: IPv4-mapped, IPv4-compatible, NAT64 (well-known, and
// local-use at its /48 and /96 positions), 6to4, ISATAP and Teredo (its
// server and its client).
func Forms(a netip.Addr) []netip.Addr {
	a = a.WithZone("").Unmap()
	out := []netip.Addr{a}
	if !a.Is6() {
		return out
	}
	b := a.As16()
	v4 := func(i, j, k, l int) netip.Addr { return netip.AddrFrom4([4]byte{b[i], b[j], b[k], b[l]}) }
	tail := v4(12, 13, 14, 15)
	switch {
	case nat64.Contains(a):
		out = append(out, tail)
	case nat64Local.Contains(a):
		out = append(out, tail, v4(6, 7, 9, 10))
	case sixToFour.Contains(a):
		out = append(out, v4(2, 3, 4, 5))
	case teredo.Contains(a):
		out = append(out, v4(4, 5, 6, 7), netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}))
	case [12]byte(b[:12]) == [12]byte{}:
		out = append(out, tail) // IPv4-compatible
	}
	if (b[8] == 0 || b[8] == 2) && b[9] == 0 && b[10] == 0x5e && b[11] == 0xfe { // ISATAP
		out = append(out, tail)
	}
	return out
}

// Result is what a scan found: the IDs of the table entries whose values it
// holds, each once, in the order first seen, and whether it holds anything
// CLK-4's patterns match. A pattern match alone is no trip.
type Result struct {
	Trips   []int
	Pattern bool
}

func (r *Result) add(id int) {
	for _, t := range r.Trips {
		if t == id {
			return
		}
	}
	r.Trips = append(r.Trips, id)
}

// Scan matches one whole message.
func (m *Matcher) Scan(b []byte) Result {
	s := m.Stream()
	s.Write(b)
	return s.Result()
}

// Stream matches a message that arrives in writes: a value or a CLK-4 token
// split across writes still matches. Not safe for concurrent use.
type Stream struct {
	m    *Matcher
	tail []byte
	res  Result
}

// Stream starts a stream.
func (m *Matcher) Stream() *Stream { return &Stream{m: m} }

// Write scans p with the stream's carried tail. It never fails.
func (s *Stream) Write(p []byte) (int, error) {
	w := append(s.tail, p...)
	for _, f := range s.m.forms {
		if bytes.Contains(w, f.b) {
			s.res.add(f.id)
		}
	}
	if !s.res.Pattern && Pattern(string(w)) {
		s.res.Pattern = true
	}
	keep := max(s.m.carry, carryPattern)
	if len(w) > keep {
		w = w[len(w)-keep:]
	}
	s.tail = append([]byte(nil), w...)
	return len(p), nil
}

// Result is what the stream has found so far.
func (s *Stream) Result() Result {
	return Result{Trips: append([]int(nil), s.res.Trips...), Pattern: s.res.Pattern}
}
