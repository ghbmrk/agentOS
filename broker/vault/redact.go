package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
)

// Placeholder replaces every redacted value.
const Placeholder = "[REDACTED]"

// KindPlanLogin is a plan login (CRED-5): a provider CLI's token set,
// stored as one JSON object (egress.PlanLogins).
const KindPlanLogin = "plan-login"

// Redactor replaces vault values in agent-bound bytes (CRED-7). It matches
// each value verbatim and in the encodings a provider or a hostile guest is
// most likely to echo it in: base64 (standard and URL-safe) at all three
// byte alignments, so the value is found inside a larger encoded blob such
// as base64("Bearer "+key); hex in any letter case; URL query and path
// escaping; and JSON string escaping. It is defense in depth: custody
// (CRED-1) does not rely on it.
//
// It can also match formats (WithFormats): a provider's credential shapes,
// so a token the vault never stored is scrubbed too.
type Redactor struct {
	pats    []pattern
	maxLen  int
	formats []*regexp.Regexp
}

// FormatMaxLen bounds what a stream holds back for formats. A Writer for a
// redactor with formats holds back the last FormatMaxLen-1 bytes of every
// write, match or not, and a format match running to the end of what it has
// seen until it ends, if it is shorter than FormatMaxLen. Of a longer match
// at least the first FormatMaxLen bytes are redacted and the rest of it may
// be emitted (TestFormatStreamHoldBounds): the built-in
// formats are prefix-anchored, so the continuation no longer matches. No
// provider token the formats describe is that long.
const FormatMaxLen = 4096

type pattern struct {
	b []byte
	// fold matches ASCII letters in any case (hex).
	fold bool
}

// redactValues returns what a vault redactor matches for one entry: its
// whole value and, for a plan login, each string inside its JSON token
// set, so a single token echoed on its own is caught too (VAULT-REDACT).
// Strings shorter than MinValueLen are left out: they could match innocent
// text and are not credentials. So are identifiers (isIdentifierKey): an
// account ID is not secret, and the placeholder login the broker hands a
// worker carries it, so matching it would corrupt that login.
func redactValues(kind string, value []byte) [][]byte {
	out := [][]byte{value}
	if kind != KindPlanLogin {
		return out
	}
	var set any
	if json.Unmarshal(value, &set) != nil {
		return out
	}
	var walk func(string, any)
	walk = func(key string, x any) {
		if isIdentifierKey(key) {
			return
		}
		switch x := x.(type) {
		case string:
			if len(x) >= MinValueLen {
				out = append(out, []byte(x))
			}
		case map[string]any:
			for k, e := range x {
				walk(k, e)
			}
		case []any:
			for _, e := range x {
				walk(key, e)
			}
		}
	}
	walk("", set)
	return out
}

// isIdentifierKey reports whether a token-set key names an identifier
// ("id", or ending "_id", such as account_id) rather than a credential.
// Every other string stays a pattern, so an unknown field is redacted.
func isIdentifierKey(k string) bool {
	return k == "id" || strings.HasSuffix(k, "_id")
}

// NewRedactor builds a redactor for values. Empty values are ignored.
func NewRedactor(values [][]byte) *Redactor {
	return (&Redactor{}).With(values...)
}

// With returns a redactor that matches everything r matches and values
// too. r is unchanged.
func (r *Redactor) With(values ...[]byte) *Redactor {
	seen := map[string]bool{}
	for _, p := range r.pats {
		seen[string(p.b)] = true
	}
	r = &Redactor{pats: append([]pattern(nil), r.pats...), maxLen: r.maxLen, formats: r.formats}
	for _, p := range encodings(values) {
		if seen[string(p.b)] {
			continue
		}
		seen[string(p.b)] = true
		r.pats = append(r.pats, p)
		if len(p.b) > r.maxLen {
			r.maxLen = len(p.b)
		}
	}
	return r
}

// WithFormats returns a redactor that matches everything r matches and
// every match of formats too, Go regular expressions with any flags inline.
// It refuses a format that does not compile or matches the empty string.
// Matches are leftmost-longest. r is unchanged.
func (r *Redactor) WithFormats(formats ...string) (*Redactor, error) {
	out := &Redactor{pats: r.pats, maxLen: r.maxLen, formats: append([]*regexp.Regexp(nil), r.formats...)}
	for _, f := range formats {
		re, err := regexp.Compile(f)
		if err != nil {
			return nil, errors.New("vault: a credential format does not compile")
		}
		if re.MatchString("") {
			return nil, errors.New("vault: a credential format matches the empty string")
		}
		re.Longest()
		out.formats = append(out.formats, re)
	}
	return out, nil
}

// encodings returns every form of values a redactor matches, without
// duplicates. Forms shorter than 4 bytes are dropped.
func encodings(values [][]byte) []pattern {
	var out []pattern
	seen := map[string]bool{}
	add := func(p string, fold bool) {
		if len(p) < 4 || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, pattern{b: []byte(p), fold: fold})
	}
	for _, v := range values {
		if len(v) == 0 {
			continue
		}
		s := string(v)
		add(s, false)
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			add(enc.EncodeToString(v), false)
			for k := 0; k < 3; k++ {
				add(alignedBase64(enc, v, k), false)
			}
		}
		add(hex.EncodeToString(v), true)
		add(url.QueryEscape(s), false)
		add(url.PathEscape(s), false)
		if js, err := json.Marshal(s); err == nil {
			add(string(js[1:len(js)-1]), false)
		}
	}
	return out
}

// alignedBase64 returns the run of base64 characters that encodes v, and
// nothing else, when v starts k bytes into a 3-byte group of a larger
// encoded stream. Characters that also depend on neighbouring bytes are
// dropped from both ends.
func alignedBase64(enc *base64.Encoding, v []byte, k int) string {
	e := enc.WithPadding(base64.NoPadding).EncodeToString(append(make([]byte, k), v...))
	n := k + len(v)
	end := 4 * (n / 3) // only complete groups
	skip := [3]int{0, 2, 3}[k]
	if end <= skip {
		return ""
	}
	return e[skip:end]
}

// MaxLen is the longest pattern, in bytes, or FormatMaxLen when r matches
// formats and no value is longer.
func (r *Redactor) MaxLen() int {
	if len(r.formats) > 0 && r.maxLen < FormatMaxLen {
		return FormatMaxLen
	}
	return r.maxLen
}

// Redact returns b with every match replaced by Placeholder.
func (r *Redactor) Redact(b []byte) []byte {
	out, rest := r.scan(nil, b, true)
	return append(out, rest...)
}

// scan appends to out the redacted form of b. When final is false it stops
// short of the last maxLen-1 bytes that could begin an incomplete match and
// returns them as rest; when final is true rest is empty.
func (r *Redactor) scan(out, b []byte, final bool) (_, rest []byte) {
	pos := 0
	for {
		i, n, format := r.earliest(b[pos:])
		if i < 0 {
			break
		}
		// A format match that runs to the end may go on in the next write:
		// hold it back whole, so none of it is emitted unredacted.
		if !final && format && pos+i+n == len(b) && n < FormatMaxLen {
			return append(out, b[pos:pos+i]...), b[pos+i:]
		}
		out = append(out, b[pos:pos+i]...)
		out = append(out, Placeholder...)
		pos += i + n
	}
	max := r.MaxLen()
	if final || max == 0 {
		return append(out, b[pos:]...), nil
	}
	// A match starting at or after keep could still be incomplete; any match
	// starting before it would lie wholly inside b and was found above.
	keep := len(b) - (max - 1)
	if keep < pos {
		keep = pos
	}
	return append(out, b[pos:keep]...), b[keep:]
}

// earliest finds the leftmost match, the longest at that position, and
// whether it is a format match.
func (r *Redactor) earliest(b []byte) (at, n int, format bool) {
	at = -1
	var lower []byte
	for _, p := range r.pats {
		hay := b
		if p.fold {
			if lower == nil {
				lower = asciiLower(b)
			}
			hay = lower
		}
		i := bytes.Index(hay, p.b)
		if i < 0 {
			continue
		}
		if at < 0 || i < at || (i == at && len(p.b) > n) {
			at, n = i, len(p.b)
		}
	}
	for _, re := range r.formats {
		// An empty match (a bare \b, say) redacts nothing: take the first
		// match with a byte in it.
		loc := re.FindIndex(b)
		if loc != nil && loc[1] == loc[0] {
			loc = nil
			for _, l := range re.FindAllIndex(b, -1) {
				if l[1] > l[0] {
					loc = l
					break
				}
			}
		}
		if loc == nil {
			continue
		}
		if at < 0 || loc[0] < at || (loc[0] == at && loc[1]-loc[0] > n) {
			at, n, format = loc[0], loc[1]-loc[0], true
		}
	}
	return at, n, format
}

// Writer returns a writer that redacts a stream on its way to w. It holds
// back the last MaxLen()-1 bytes, which could begin a match split across
// writes, and a format match running to the end as FormatMaxLen says; Close
// writes them. Close does not close w.
func (r *Redactor) Writer(w io.Writer) *Writer { return &Writer{r: r, w: w} }

// scanner is what a Writer streams through: Redactor or HashRedactor.
type scanner interface {
	scan(out, b []byte, final bool) (_, rest []byte)
}

// Writer is a redacting stream writer.
type Writer struct {
	r   scanner
	w   io.Writer
	buf []byte
}

// Write redacts and forwards everything that can no longer be part of a
// match. It reports len(p) on success.
func (w *Writer) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	out, rest := w.r.scan(nil, w.buf, false)
	w.buf = append(w.buf[:0], rest...)
	if len(out) > 0 {
		if _, err := w.w.Write(out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// Close redacts and writes whatever is held back.
func (w *Writer) Close() error {
	out, _ := w.r.scan(nil, w.buf, true)
	w.buf = nil
	if len(out) == 0 {
		return nil
	}
	_, err := w.w.Write(out)
	return err
}

// asciiLower lowers ASCII letters only, so offsets match the input.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}
