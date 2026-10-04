package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
)

// Placeholder replaces every redacted value.
const Placeholder = "[REDACTED]"

// Redactor replaces vault values in agent-bound bytes (CRED-7). It matches
// each value verbatim and in the encodings a provider or a hostile guest is
// most likely to echo it in: base64 (standard and URL-safe, padded or not),
// lowercase and uppercase hex, and URL query escaping. It is defense in
// depth: custody (CRED-1) does not rely on it.
type Redactor struct {
	pats   [][]byte
	maxLen int
}

// NewRedactor builds a redactor for values. Empty values are ignored.
func NewRedactor(values [][]byte) *Redactor {
	r := &Redactor{}
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		r.pats = append(r.pats, []byte(p))
		if len(p) > r.maxLen {
			r.maxLen = len(p)
		}
	}
	for _, v := range values {
		if len(v) == 0 {
			continue
		}
		s := string(v)
		add(s)
		add(base64.StdEncoding.EncodeToString(v))
		add(base64.RawStdEncoding.EncodeToString(v))
		add(base64.URLEncoding.EncodeToString(v))
		add(base64.RawURLEncoding.EncodeToString(v))
		add(hex.EncodeToString(v))
		add(string(bytes.ToUpper([]byte(hex.EncodeToString(v)))))
		add(url.QueryEscape(s))
		add(url.PathEscape(s))
	}
	return r
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
	for _, p := range r.pats {
		i := bytes.Index(b, p)
		if i < 0 {
			continue
		}
		if at < 0 || i < at || (i == at && len(p) > n) {
			at, n = i, len(p)
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
