package kernel

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"unicode/utf8"
)

// asLogged is v as the log holds it: a JSON round trip, which writes text
// that is not UTF-8 as U+FFFD. A value JSON cannot round-trip is refused with
// the encoding's own error, so the caller is told why (#4760); text the log
// rewrites is not an error here, and Append refuses an entry that holds it.
func asLogged[T any](v T) (T, error) {
	var out T
	b, err := json.Marshal(v)
	if err == nil {
		err = json.Unmarshal(b, &out)
	}
	if err != nil {
		return out, fmt.Errorf("kernel: the log cannot hold this %T: %w", v, err)
	}
	return out, nil
}

// Signing domains. A log head and a key never verify as one another (KEY-3).
const (
	DomainHead  = "agentos.head.v1\x00"
	domainEntry = "agentos.log.entry.v1\x00"
)

var (
	ErrCorrupt   = errors.New("log: corrupt")
	ErrTruncated = errors.New("log: shorter than its anchor")
	ErrFork      = errors.New("log: history differs from its anchor")
	ErrUnknown   = errors.New("log: unknown entry type or version")
	ErrBroken    = errors.New("log: a write failed; reopen")
	ErrNoSigner  = errors.New("log: no head signer")
	ErrNoLog     = errors.New("log: not opened; Open is the only constructor")
	ErrBackward  = errors.New("log: an entry's time is before the entry before it")
)

// Hash is the chain link.
type Hash [32]byte

func (h Hash) MarshalText() ([]byte, error) { return []byte(hex.EncodeToString(h[:])), nil }

func (h *Hash) UnmarshalText(b []byte) error {
	d, err := hex.DecodeString(string(b))
	if err != nil || len(d) != len(h) {
		return ErrCorrupt
	}
	copy(h[:], d)
	return nil
}

// Entry is one typed, versioned log record (LOG-5). Hash covers every field,
// so one change anywhere breaks every later link (LOG-2).
type Entry struct {
	Seq  uint64 `json:"seq"`
	Prev Hash   `json:"prev"`
	At   int64  `json:"at"` // unix ms: the kernel's reading's Earliest, never below the entry before
	// Late is the reading's Latest when it is past At (TIM-1), so Rederive
	// checks a move that time decided from the log alone.
	Late *int64          `json:"late,omitempty"`
	Type string          `json:"type"`
	V    int             `json:"v"`
	Body json.RawMessage `json:"body"`
}

func (e Entry) Hash() Hash {
	b, _ := json.Marshal(e)
	return sha256.Sum256(append([]byte(domainEntry), b...))
}

// Head names the log at one point; the kernel sub-key signs it, and an anchor
// outside the log's disk keeps it (LOG-2).
type Head struct {
	Seq  uint64 `json:"seq"`
	Hash Hash   `json:"hash"`
	Sig  []byte `json:"sig"`
}

func headMsg(seq uint64, h Hash) []byte {
	b := binary.BigEndian.AppendUint64([]byte(DomainHead), seq)
	return append(b, h[:]...)
}

func SignHead(priv ed25519.PrivateKey, seq uint64, h Hash) Head {
	return Head{Seq: seq, Hash: h, Sig: ed25519.Sign(priv, headMsg(seq, h))}
}

func (h Head) Valid(pub ed25519.PublicKey) bool {
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, headMsg(h.Seq, h.Hash), h.Sig)
}

// Store is an append-only byte stream. Append must be durable when it
// returns. Truncate cuts the stream to n bytes.
type Store interface {
	Append(b []byte) error
	ReadAll() ([]byte, error)
	Truncate(n int) error
}

// Anchor keeps the newest head somewhere the log's disk cannot rewrite: the
// owner's phone, a TPM counter, the enforcer (LOG-2).
type Anchor interface {
	Put(Head) error
	Latest() (Head, bool)
}

// MemStore and MemAnchor are the in-memory implementations.
type MemStore struct{ B []byte }

func (m *MemStore) Append(b []byte) error { m.B = append(m.B, b...); return nil }
func (m *MemStore) ReadAll() ([]byte, error) {
	return append([]byte(nil), m.B...), nil
}
func (m *MemStore) Truncate(n int) error {
	if n < 0 || n > len(m.B) {
		return ErrCorrupt
	}
	m.B = m.B[:n]
	return nil
}

type MemAnchor struct {
	H  Head
	Ok bool
}

func (m *MemAnchor) Put(h Head) error     { m.H, m.Ok = h, true; return nil }
func (m *MemAnchor) Latest() (Head, bool) { return m.H, m.Ok }

// Config opens a log. Sign may be nil for a read-only audit.
type Config struct {
	Store  Store
	Anchor Anchor
	Key    [32]byte          // AES-256-GCM key, sealed to the core's TPM in production
	Pub    ed25519.PublicKey // verifies anchored heads
	Sign   ed25519.PrivateKey
	// Rand is the kernel's one random source: log and content nonces, and
	// subject IDs and data keys (erase.go). Production (proc) pins it to
	// crypto/rand; tests, the sim and eval runs seed it.
	Rand io.Reader
}

// Format prints a Config as its type alone, never the log key or the box's
// signing key (CLK-1). Like Kernel.Format, fmt skips it under %w and %p,
// and inside an unexported holder (DECOY-b-8).
func (Config) Format(f fmt.State, _ rune) { fmt.Fprint(f, "kernel.Config") }

// Log is the one append-only, encrypted, hash-chained record (LOG-1, LOG-2).
// Open is its only constructor: a zero Log, or a nil *Log, fails closed with
// ErrNoLog. A copy of a Log is the same log, since both reach one record
// through p, so copies never diverge from each other or the store.
type Log struct{ p **logFields } // fmt prints p as an address in every verb, at any depth (DECOY-b-8)
type logFields struct {
	cfg     Config
	aead    cipher.AEAD
	entries []Entry
	broken  bool
}

// fields is l's record, or ErrNoLog for a Log that Open did not make.
func (l *Log) fields() (*logFields, error) {
	if l == nil || l.p == nil || *l.p == nil {
		return nil, ErrNoLog
	}
	return *l.p, nil
}

func newAEAD(key [32]byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func aad(seq uint64) []byte { return binary.BigEndian.AppendUint64(nil, seq) }

// Open reads, authenticates and checks the whole log against its anchor. A
// log shorter than its anchor, or with another entry at the anchored seq, is
// refused before a torn final frame is trimmed, so a refusal cuts no byte
// (LOG-2). A last widening entry no anchor covers is dropped: only an
// owner-confirmed widening counts (KRN-7). Narrowing, dispatch and result
// entries are always kept, since dropping one could repeat an effect (KRN-8).
func Open(cfg Config) (*Log, error) {
	a, err := newAEAD(cfg.Key)
	if err != nil {
		return nil, err
	}
	f := &logFields{cfg: cfg, aead: a}
	raw, err := cfg.Store.ReadAll()
	if err != nil {
		return nil, err
	}
	var ends []int // the byte offset after each entry read, where dropUnconfirmed cuts a tail
	off := 0
	for off < len(raw) {
		if len(raw)-off < 4 {
			break // torn length
		}
		n := int(binary.BigEndian.Uint32(raw[off:]))
		if n < a.NonceSize()+a.Overhead() || off+4+n > len(raw) {
			if n < a.NonceSize()+a.Overhead() && off+4+n <= len(raw) {
				return nil, ErrCorrupt
			}
			break // torn body
		}
		seq := uint64(len(f.entries) + 1)
		fr := raw[off+4 : off+4+n]
		pt, err := a.Open(nil, fr[:a.NonceSize()], fr[a.NonceSize():], aad(seq))
		if err != nil {
			if off+4+n == len(raw) {
				break // torn final frame
			}
			return nil, ErrCorrupt
		}
		var e Entry
		if json.Unmarshal(pt, &e) != nil || e.Seq != seq {
			return nil, ErrCorrupt
		}
		if seq > 1 && e.Prev != f.entries[seq-2].Hash() || seq == 1 && e.Prev != (Hash{}) {
			return nil, ErrCorrupt
		}
		if !Known(e.Type, e.V) {
			return nil, ErrUnknown
		}
		f.entries = append(f.entries, e)
		off += 4 + n
		ends = append(ends, off)
	}
	if err := f.checkAnchor(); err != nil {
		return nil, err
	}
	if off < len(raw) {
		if err := cfg.Store.Truncate(off); err != nil {
			return nil, err
		}
	}
	if err := f.dropUnconfirmed(ends); err != nil {
		return nil, err
	}
	return &Log{&f}, nil
}

func (f *logFields) checkAnchor() error {
	if f.cfg.Anchor == nil {
		return nil
	}
	h, ok := f.cfg.Anchor.Latest()
	if !ok {
		return nil
	}
	if !h.Valid(f.cfg.Pub) {
		return ErrCorrupt
	}
	if h.Seq > uint64(len(f.entries)) {
		return ErrTruncated
	}
	if h.Seq == 0 {
		return nil
	}
	if f.entries[h.Seq-1].Hash() != h.Hash {
		return ErrFork
	}
	return nil
}

// dropUnconfirmed removes trailing widening entries that no anchor covers;
// ends is Open's offset after each entry it read, valid only there.
func (f *logFields) dropUnconfirmed(ends []int) error {
	var covered uint64
	if f.cfg.Anchor != nil {
		if h, ok := f.cfg.Anchor.Latest(); ok {
			covered = h.Seq
		}
	}
	n := len(f.entries)
	for uint64(n) > covered && Widening(f.entries[n-1].Type) {
		n--
	}
	if n == len(f.entries) {
		return nil
	}
	cut := 0
	if n > 0 {
		cut = ends[n-1]
	}
	if err := f.cfg.Store.Truncate(cut); err != nil {
		return err
	}
	f.entries = f.entries[:n]
	return nil
}

// Append seals and writes one entry. After a failed write the log refuses
// everything until reopened, so a torn frame is trimmed by Open and never
// built on.
func (l *Log) Append(at int64, typ string, v int, body any) (Entry, error) {
	return l.append(At(at), typ, v, body)
}

// lastAt is the last entry's time; an empty or unopened log floors nothing.
func (l *Log) lastAt() int64 {
	f, err := l.fields()
	if err != nil || len(f.entries) == 0 {
		return math.MinInt64
	}
	return f.entries[len(f.entries)-1].At
}

// append logs body at reading r. A reading before the last entry is
// refused, so the log's times never decrease (TIM-1).
func (l *Log) append(r Reading, typ string, v int, body any) (Entry, error) {
	f, err := l.fields()
	if err != nil {
		return Entry{}, err
	}
	if f.broken {
		return Entry{}, ErrBroken
	}
	if !Known(typ, v) {
		return Entry{}, ErrUnknown
	}
	bb, err := json.Marshal(body)
	if err != nil {
		return Entry{}, err
	}
	// json.Marshal writes text that is not UTF-8 as the escape \ufffd (and a
	// valid U+FFFD as is): such an entry would name what its caller did not,
	// and a lookup by the caller's text would miss it (KRN-1, #4719).
	if bytes.Contains(bytes.ReplaceAll(bb, []byte(`\\`), nil), []byte(`\ufffd`)) || !utf8.Valid(bb) {
		return Entry{}, ErrNotText
	}
	e := Entry{Seq: uint64(len(f.entries) + 1), At: r.Earliest, Type: typ, V: v, Body: bb}
	if r.Latest > r.Earliest {
		e.Late = &r.Latest
	}
	if len(f.entries) > 0 {
		last := f.entries[len(f.entries)-1]
		if e.At < last.At {
			return Entry{}, ErrBackward
		}
		e.Prev = last.Hash()
	}
	pt, _ := json.Marshal(e)
	nonce := make([]byte, f.aead.NonceSize())
	if _, err := io.ReadFull(f.cfg.Rand, nonce); err != nil {
		return Entry{}, fmt.Errorf("log: nonce: %w", err)
	}
	ct := f.aead.Seal(nonce, nonce, pt, aad(e.Seq))
	fr := binary.BigEndian.AppendUint32(nil, uint32(len(ct)))
	fr = append(fr, ct...)
	if err := f.cfg.Store.Append(fr); err != nil {
		f.broken = true
		return Entry{}, err
	}
	f.entries = append(f.entries, e)
	return e, nil
}

// Anchor signs the current head and hands it to the anchor. A widening is
// confirmed once this returns.
func (l *Log) Anchor() error {
	f, err := l.fields()
	if err != nil {
		return err
	}
	if f.cfg.Sign == nil || f.cfg.Anchor == nil {
		return ErrNoSigner
	}
	if len(f.entries) == 0 {
		return nil
	}
	last := f.entries[len(f.entries)-1]
	return f.cfg.Anchor.Put(SignHead(f.cfg.Sign, last.Seq, last.Hash()))
}

// Entries and Len are the log's entries and their count: none for a Log
// Open did not make.
func (l *Log) Entries() []Entry {
	f, err := l.fields()
	if err != nil {
		return nil
	}
	return f.entries
}

func (l *Log) Len() int { return len(l.Entries()) }

// Same reports whether two logs hold byte-identical histories.
func Same(a, b []Entry) bool {
	return slices.EqualFunc(a, b, func(x, y Entry) bool { return x.Hash() == y.Hash() && bytes.Equal(x.Body, y.Body) })
}
