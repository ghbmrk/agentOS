package vault

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

// HashWindow is the length, in bytes, of the windows a HashRedactor keeps
// keyed hashes of. A form shorter than it is hashed whole.
const HashWindow = 24

// HashRedactor redacts vault values without holding them (SIM-split). It
// is built where the plaintext is (the unlock step) and handed to egress,
// which then redacts every account's values on every response and
// journaled path while holding only keyed hashes (CRED-7). For each form a
// Redactor matches (encodings), it keeps a keyed hash of the head window
// and of the tail window, and of the whole form: a head hit followed by
// the whole form redacts the whole form, and a head or tail hit alone (a
// truncated echo) redacts the window. Only two windows per form are kept,
// so overlapping windows cannot be chained to recover a value byte by
// byte. A rolling fingerprint with a secret base finds candidate spans;
// each is confirmed by HMAC-SHA-256 before it is redacted.
type HashRedactor struct {
	key    []byte
	base   uint64
	probes []*probe
	maxLen int
}

// probe is every hashed window of one length, in one case mode.
type probe struct {
	n    int
	fold bool
	pow  uint64 // base^n
	hits map[uint32][]hashHit
}

type hashHit struct {
	sum [16]byte
	// full is the whole form's length when this window is its head, and
	// fullSum its hash; zero when the window stands alone.
	full    int
	fullSum [16]byte
}

// NewHashRedactor builds a redactor over values that keeps no part of
// them. Empty values are ignored.
func NewHashRedactor(values [][]byte) (*HashRedactor, error) {
	key := make([]byte, 32)
	var b [8]byte
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	r := &HashRedactor{key: key, base: binary.LittleEndian.Uint64(b[:]) | 1}
	for _, p := range encodings(values) {
		form := p.b
		if len(form) <= HashWindow {
			r.add(hashEntry{N: len(form), Fold: p.fold, Pre: r.print(form), Sum: r.mac(form)})
			continue
		}
		head, tail := form[:HashWindow], form[len(form)-HashWindow:]
		r.add(hashEntry{N: HashWindow, Fold: p.fold, Pre: r.print(head), Sum: r.mac(head), Full: len(form), FullSum: r.mac(form)})
		r.add(hashEntry{N: HashWindow, Fold: p.fold, Pre: r.print(tail), Sum: r.mac(tail)})
	}
	return r, nil
}

// hashEntry is one hashed window, and its wire form.
type hashEntry struct {
	N       int    `json:"n"`
	Fold    bool   `json:"f,omitempty"`
	Pre     uint32 `json:"p"`
	Sum     []byte `json:"s"`
	Full    int    `json:"l,omitempty"`
	FullSum []byte `json:"ls,omitempty"`
}

func (r *HashRedactor) add(e hashEntry) {
	var pr *probe
	for _, q := range r.probes {
		if q.n == e.N && q.fold == e.Fold {
			pr = q
		}
	}
	if pr == nil {
		pow := uint64(1)
		for i := 0; i < e.N; i++ {
			pow *= r.base
		}
		pr = &probe{n: e.N, fold: e.Fold, pow: pow, hits: map[uint32][]hashHit{}}
		r.probes = append(r.probes, pr)
	}
	h := hashHit{full: e.Full}
	copy(h.sum[:], e.Sum)
	copy(h.fullSum[:], e.FullSum)
	pr.hits[e.Pre] = append(pr.hits[e.Pre], h)
	for _, n := range []int{e.N, e.Full} {
		if n > r.maxLen {
			r.maxLen = n
		}
	}
}

func (r *HashRedactor) mac(b []byte) []byte {
	m := hmac.New(sha256.New, r.key)
	m.Write(b)
	return m.Sum(nil)[:16]
}

// print is the rolling fingerprint of b: its top 32 bits only.
func (r *HashRedactor) print(b []byte) uint32 {
	var h uint64
	for _, c := range b {
		h = h*r.base + uint64(c) + 1
	}
	return uint32(h >> 32)
}

// MaxLen is the longest span the redactor can match, in bytes.
func (r *HashRedactor) MaxLen() int { return r.maxLen }

// Redact returns b with every match replaced by Placeholder.
func (r *HashRedactor) Redact(b []byte) []byte {
	out, rest := r.scan(nil, b, true)
	return append(out, rest...)
}

// Writer returns a writer that redacts a stream on its way to w, holding
// back at most MaxLen()-1 bytes; Close writes them. Close does not close w.
func (r *HashRedactor) Writer(w io.Writer) *Writer { return &Writer{r: r, w: w} }

// scan is Redactor.scan's contract: when final is false, no match is
// decided at a position whose longest possible span could still run past
// b, so the result does not depend on how a stream was split.
func (r *HashRedactor) scan(out, b []byte, final bool) (_, rest []byte) {
	limit := len(b)
	if !final && r.maxLen > 0 {
		limit = len(b) - (r.maxLen - 1)
	}
	var plain, lower []uint64
	var low []byte
	pos := 0
	for i := 0; i < limit; i++ {
		best := 0
		for _, pr := range r.probes {
			if i+pr.n > len(b) {
				continue
			}
			hay, pre := b, &plain
			if pr.fold {
				if low == nil {
					low = asciiLower(b)
				}
				hay, pre = low, &lower
			}
			if *pre == nil {
				*pre = r.prefix(hay)
			}
			h := (*pre)[i+pr.n] - (*pre)[i]*pr.pow
			hits := pr.hits[uint32(h>>32)]
			if len(hits) == 0 {
				continue
			}
			sum := r.mac(hay[i : i+pr.n])
			for _, hit := range hits {
				if !hmac.Equal(sum, hit.sum[:]) {
					continue
				}
				n := pr.n
				if hit.full > 0 && i+hit.full <= len(b) && hmac.Equal(r.mac(hay[i:i+hit.full]), hit.fullSum[:]) {
					n = hit.full
				}
				if n > best {
					best = n
				}
			}
		}
		if best > 0 {
			out = append(out, b[pos:i]...)
			out = append(out, Placeholder...)
			pos = i + best
			i = pos - 1
		}
	}
	if final {
		return append(out, b[pos:]...), nil
	}
	keep := limit
	if keep < pos {
		keep = pos
	}
	if keep < 0 {
		keep = 0
	}
	return append(out, b[pos:keep]...), b[keep:]
}

// prefix returns the rolling prefix fingerprints of b, so any window's
// fingerprint is two lookups.
func (r *HashRedactor) prefix(b []byte) []uint64 {
	h := make([]uint64, len(b)+1)
	for i, c := range b {
		h[i+1] = h[i]*r.base + uint64(c) + 1
	}
	return h
}

type hashWire struct {
	Key     []byte      `json:"k"`
	Base    uint64      `json:"b"`
	Entries []hashEntry `json:"e"`
}

// MarshalBinary encodes the redactor for the hand from the unlock step to
// egress. The encoding holds keyed hashes and the key, never a value.
func (r *HashRedactor) MarshalBinary() ([]byte, error) {
	w := hashWire{Key: r.key, Base: r.base}
	for _, pr := range r.probes {
		for pre, hits := range pr.hits {
			for _, h := range hits {
				e := hashEntry{N: pr.n, Fold: pr.fold, Pre: pre, Sum: append([]byte(nil), h.sum[:]...), Full: h.full}
				if h.full > 0 {
					e.FullSum = append([]byte(nil), h.fullSum[:]...)
				}
				w.Entries = append(w.Entries, e)
			}
		}
	}
	return json.Marshal(w)
}

// UnmarshalBinary replaces r with the encoded redactor.
func (r *HashRedactor) UnmarshalBinary(b []byte) error {
	var w hashWire
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	if len(w.Key) != 32 || w.Base&1 == 0 {
		return errors.New("vault: bad hash redactor key")
	}
	n := &HashRedactor{key: w.Key, base: w.Base}
	for _, e := range w.Entries {
		if e.N < 4 || e.N > HashWindow || len(e.Sum) != 16 ||
			(e.Full != 0 && (e.Full <= e.N || len(e.FullSum) != 16)) {
			return errors.New("vault: bad hash redactor entry")
		}
		n.add(e)
	}
	*r = *n
	return nil
}

// HashRedactor builds a HashRedactor over every entry.
func (v *Vault) HashRedactor() (*HashRedactor, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil, ErrClosed
	}
	vals := make([][]byte, 0, len(v.entries))
	for _, r := range v.entries {
		vals = append(vals, redactValues(r.Kind, r.Value)...)
	}
	return NewHashRedactor(vals)
}
