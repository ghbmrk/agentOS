package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
)

// Placeholder replaces every redacted value.
const Placeholder = "[REDACTED]"

// Redactor replaces vault values in agent-bound bytes (CRED-7). It matches
// each value verbatim and in the encodings a provider or a hostile guest is
// most likely to echo it in: base64 (standard and URL-safe) at all three
// byte alignments, so the value is found inside a larger encoded blob such
// as base64("Bearer "+key); hex in any letter case; URL query and path
// escaping; and JSON string escaping. It is defense in depth: custody
// (CRED-1) does not rely on it.
type Redactor struct {
	pats   []pattern
	maxLen int
}

type pattern struct {
	b []byte
	// fold matches ASCII letters in any case (hex).
	fold bool
}

// NewRedactor builds a redactor for values. Empty values are ignored.
func NewRedactor(values [][]byte) *Redactor {
	r := &Redactor{}
	seen := map[string]bool{}
	add := func(p string, fold bool) {
		if len(p) < 4 || seen[p] {
			return
		}
		seen[p] = true
		r.pats = append(r.pats, pattern{b: []byte(p), fold: fold})
		if len(p) > r.maxLen {
			r.maxLen = len(p)
		}
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
	return r
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

// MaxLen is the longest pattern, in bytes.
func (r *Redactor) MaxLen() int { return r.maxLen }

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
		i, n := r.earliest(b[pos:])
		if i < 0 {
			break
		}
		out = append(out, b[pos:pos+i]...)
		out = append(out, Placeholder...)
		pos += i + n
	}
	if final || r.maxLen == 0 {
		return append(out, b[pos:]...), nil
	}
	// A match starting at or after keep could still be incomplete; any match
	// starting before it would lie wholly inside b and was found above.
	keep := len(b) - (r.maxLen - 1)
	if keep < pos {
		keep = pos
	}
	return append(out, b[pos:keep]...), b[keep:]
}

// earliest finds the leftmost match, the longest at that position.
func (r *Redactor) earliest(b []byte) (at, n int) {
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
	return at, n
}

// Writer returns a writer that redacts a stream on its way to w. It holds
// back at most MaxLen()-1 bytes that could begin a match split across
// writes; Close writes them. Close does not close w.
func (r *Redactor) Writer(w io.Writer) *Writer { return &Writer{r: r, w: w} }

// Writer is a redacting stream writer.
type Writer struct {
	r   *Redactor
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
