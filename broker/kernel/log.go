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
)

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
	Seq  uint64          `json:"seq"`
	Prev Hash            `json:"prev"`
	At   int64           `json:"at"` // unix ms, the kernel's clock
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
	Rand   io.Reader // nonces: crypto/rand in production, seeded in the sim
}

// Log is the one append-only, encrypted, hash-chained record (LOG-1, LOG-2).
type Log struct {
	cfg     Config
	aead    cipher.AEAD
	entries []Entry
	ends    []int // byte offset after each entry, to cut a tail
	broken  bool
}

func newAEAD(key [32]byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func aad(seq uint64) []byte { return binary.BigEndian.AppendUint64(nil, seq) }

// Open reads, authenticates and checks the whole log against its anchor.
// A torn final frame is trimmed. A log shorter than its anchor, or with a
// different entry at the anchored seq, is refused. A widening entry that no
// anchor covers, as the last entry, is dropped: only an owner-confirmed
// widening counts (KRN-7). Narrowing, dispatch and result entries are
// always kept, since dropping one could repeat an effect (KRN-8).
func Open(cfg Config) (*Log, error) {
	a, err := newAEAD(cfg.Key)
	if err != nil {
		return nil, err
	}
	l := &Log{cfg: cfg, aead: a}
	raw, err := cfg.Store.ReadAll()
	if err != nil {
		return nil, err
	}
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
		seq := uint64(len(l.entries) + 1)
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
		if seq > 1 && e.Prev != l.entries[seq-2].Hash() || seq == 1 && e.Prev != (Hash{}) {
			return nil, ErrCorrupt
		}
		if !Known(e.Type, e.V) {
			return nil, ErrUnknown
		}
		l.entries = append(l.entries, e)
		off += 4 + n
		l.ends = append(l.ends, off)
	}
	if off < len(raw) {
		if err := cfg.Store.Truncate(off); err != nil {
			return nil, err
		}
	}
	if err := l.checkAnchor(); err != nil {
		return nil, err
	}
	if err := l.dropUnconfirmed(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) checkAnchor() error {
	if l.cfg.Anchor == nil {
		return nil
	}
	h, ok := l.cfg.Anchor.Latest()
	if !ok {
		return nil
	}
	if !h.Valid(l.cfg.Pub) {
		return ErrCorrupt
	}
	if h.Seq > uint64(len(l.entries)) {
		return ErrTruncated
	}
	if h.Seq == 0 {
		return nil
	}
	if l.entries[h.Seq-1].Hash() != h.Hash {
		return ErrFork
	}
	return nil
}

// dropUnconfirmed removes trailing widening entries that no anchor covers.
func (l *Log) dropUnconfirmed() error {
	var covered uint64
	if l.cfg.Anchor != nil {
		if h, ok := l.cfg.Anchor.Latest(); ok {
			covered = h.Seq
		}
	}
	n := len(l.entries)
	for n > 0 && uint64(n) > covered && Widening(l.entries[n-1].Type) {
		n--
	}
	if n == len(l.entries) {
		return nil
	}
	cut := 0
	if n > 0 {
		cut = l.ends[n-1]
	}
	if err := l.cfg.Store.Truncate(cut); err != nil {
		return err
	}
	l.entries, l.ends = l.entries[:n], l.ends[:n]
	return nil
}

// Append seals and writes one entry. After a failed write the log refuses
// everything until reopened, so a torn frame is trimmed by Open and never
// built on.
func (l *Log) Append(at int64, typ string, v int, body any) (Entry, error) {
	if l.broken {
		return Entry{}, ErrBroken
	}
	if !Known(typ, v) {
		return Entry{}, ErrUnknown
	}
	bb, err := json.Marshal(body)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{Seq: uint64(len(l.entries) + 1), At: at, Type: typ, V: v, Body: bb}
	if len(l.entries) > 0 {
		e.Prev = l.entries[len(l.entries)-1].Hash()
	}
	pt, _ := json.Marshal(e)
	nonce := make([]byte, l.aead.NonceSize())
	if _, err := io.ReadFull(l.cfg.Rand, nonce); err != nil {
		return Entry{}, fmt.Errorf("log: nonce: %w", err)
	}
	ct := l.aead.Seal(nonce, nonce, pt, aad(e.Seq))
	fr := binary.BigEndian.AppendUint32(nil, uint32(len(ct)))
	fr = append(fr, ct...)
	if err := l.cfg.Store.Append(fr); err != nil {
		l.broken = true
		return Entry{}, err
	}
	l.entries = append(l.entries, e)
	prev := 0
	if len(l.ends) > 0 {
		prev = l.ends[len(l.ends)-1]
	}
	l.ends = append(l.ends, prev+len(fr))
	return e, nil
}

// Anchor signs the current head and hands it to the anchor. A widening is
// confirmed once this returns.
func (l *Log) Anchor() error {
	if l.cfg.Sign == nil || l.cfg.Anchor == nil {
		return ErrNoSigner
	}
	if len(l.entries) == 0 {
		return nil
	}
	last := l.entries[len(l.entries)-1]
	return l.cfg.Anchor.Put(SignHead(l.cfg.Sign, last.Seq, last.Hash()))
}

func (l *Log) Entries() []Entry { return l.entries }
func (l *Log) Len() int         { return len(l.entries) }

// Same reports whether two logs hold byte-identical histories.
func Same(a, b []Entry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Hash() != b[i].Hash() || !bytes.Equal(a[i].Body, b[i].Body) {
			return false
		}
	}
	return true
}
