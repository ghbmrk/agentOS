package kernel_test

// REQ: LOG-1, LOG-2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// frameKey is the log key these tests seal frames under by hand; a func, not
// a package var, so it widens no mutation targets.
func frameKey() [32]byte { return [32]byte{7} }

// frameCfg is a log config over st and a with frameKey and its own signer.
func frameCfg(st kernel.Store, a kernel.Anchor) kernel.Config {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	return kernel.Config{Store: st, Anchor: a, Key: frameKey(), Pub: priv.Public().(ed25519.PublicKey), Sign: priv, Rand: rand.NewChaCha8([32]byte{4})}
}

// frameLog is the bytes of a log holding two task entries.
func frameLog(t *testing.T) []byte {
	t.Helper()
	st := &kernel.MemStore{}
	l, err := kernel.Open(frameCfg(st, nil))
	if err != nil {
		t.Fatal(err)
	}
	for i, task := range []string{"a", "b"} {
		if _, err := l.Append(int64(i), kernel.TTaskOpened, 1, map[string]string{"task": task}); err != nil {
			t.Fatal(err)
		}
	}
	return bytes.Clone(st.B)
}

// sealFrame is e sealed as the log seals entry seq: a big-endian length,
// then a nonce and the AES-GCM sealing of e's JSON with seq as the aad.
func sealFrame(t *testing.T, seq uint64, e kernel.Entry) []byte {
	t.Helper()
	key := frameKey()
	b, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	fr := g.Seal(make([]byte, g.NonceSize()), make([]byte, g.NonceSize()), pt, binary.BigEndian.AppendUint64(nil, seq))
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(fr))), fr...)
}

// A hash's text form is exactly 64 hex digits (LOG-2): text that is not
// hex, or hex of another length, is corrupt and leaves the hash unchanged.
// Catches the check dropped, which would take a short or garbled link.
func TestHashTextIsExact(t *testing.T) {
	for _, s := range []string{"zz", "00", hexOf(33)} {
		h := kernel.Hash{9}
		if err := h.UnmarshalText([]byte(s)); !errors.Is(err, kernel.ErrCorrupt) || h != (kernel.Hash{9}) {
			t.Fatalf("hash text %q: %v, hash %x", s, err, h)
		}
	}
	var h kernel.Hash
	if err := h.UnmarshalText([]byte(hexOf(32))); err != nil || h != kernel.Hash(bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatalf("a 32-byte hash: %v, %x", err, h)
	}
}

// hexOf is n bytes of 0xab as hex.
func hexOf(n int) string { return string(bytes.Repeat([]byte("ab"), n)) }

// MemStore cuts only to a length it holds (LOG-2): below zero or past its
// end is corrupt and cuts nothing; its own length and zero both cut.
// Catches either bound dropped or moved by one.
func TestMemStoreTruncateBounds(t *testing.T) {
	m := &kernel.MemStore{B: []byte{1, 2, 3}}
	for _, n := range []int{-1, 4} {
		if err := m.Truncate(n); !errors.Is(err, kernel.ErrCorrupt) || len(m.B) != 3 {
			t.Fatalf("truncate to %d: %v, %d bytes left", n, err, len(m.B))
		}
	}
	if err := m.Truncate(3); err != nil || len(m.B) != 3 {
		t.Fatalf("truncate to its length: %v, %d bytes", err, len(m.B))
	}
	if err := m.Truncate(0); err != nil || len(m.B) != 0 {
		t.Fatalf("truncate to zero: %v, %d bytes", err, len(m.B))
	}
}

// Open reads each frame by its length (LOG-1, LOG-2). A whole last frame is
// an entry; a tail too short to hold a length, or a frame cut short, is torn
// and trimmed; a whole frame too short for a nonce and tag, or a whole frame
// that does not open with more bytes after it, is corrupt and cuts nothing.
// Catches each bound in the frame reader dropped, inverted or moved by one.
func TestOpenFrameBounds(t *testing.T) {
	whole := frameLog(t)
	header := func(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }
	short := append(header(5), 1, 2, 3, 4, 5)
	garbage := append(header(28), make([]byte, 28)...)
	cases := []struct {
		name    string
		tail    []byte
		entries int // -1: refused as corrupt
	}{
		{"nothing after", nil, 2},
		{"1-byte tail", []byte{0}, 2},
		{"3-byte tail", []byte{0, 0, 0}, 2},
		{"zero-length frame", header(0), -1},
		{"whole short frame", short, -1},
		{"torn short frame", short[:6], 2},
		{"torn frame, 2 bytes short", append(header(100), make([]byte, 98)...), 2},
		{"unopenable frame before more bytes", append(bytes.Clone(garbage), 0, 0), -1},
	}
	for _, c := range cases {
		for _, prefix := range [][]byte{whole, nil} {
			st := &kernel.MemStore{B: append(bytes.Clone(prefix), c.tail...)}
			before := bytes.Clone(st.B)
			l, err := kernel.Open(frameCfg(st, nil))
			want := c.entries
			if prefix == nil && want > 0 {
				want = 0
			}
			if want < 0 {
				if !errors.Is(err, kernel.ErrCorrupt) || !bytes.Equal(st.B, before) {
					t.Fatalf("%s (prefix %d bytes): %v, store changed %v", c.name, len(prefix), err, !bytes.Equal(st.B, before))
				}
				continue
			}
			if err != nil || l.Len() != want || !bytes.Equal(st.B, prefix) {
				t.Fatalf("%s (prefix %d bytes): %v, want %d entries and the tail trimmed", c.name, len(prefix), err, want)
			}
		}
	}
}

// An entry sealed under the log's key and seq, chained right, of a type
// the kernel does not know, refuses the open (LOG-5).
// Catches the unknown-type check dropped.
func TestOpenRefusesUnknownType(t *testing.T) {
	st := &kernel.MemStore{B: sealFrame(t, 1, kernel.Entry{Seq: 1, Type: "no.such.type", V: 1, Body: json.RawMessage(`{}`)})}
	if _, err := kernel.Open(frameCfg(st, nil)); !errors.Is(err, kernel.ErrUnknown) {
		t.Fatalf("an unknown entry type: %v", err)
	}
	st = &kernel.MemStore{B: sealFrame(t, 1, kernel.Entry{Seq: 1, Type: kernel.TTaskOpened, V: 1, Body: json.RawMessage(`{"task":"t"}`)})}
	if l, err := kernel.Open(frameCfg(st, nil)); err != nil || l.Len() != 1 {
		t.Fatalf("a known entry sealed by hand: %v", err)
	}
}

// A signed head at seq 0 names no entry, so it holds every log (LOG-2).
// Catches the zero check dropped, which reads the entry before the first.
func TestOpenUnderZeroHead(t *testing.T) {
	cfg := frameCfg(&kernel.MemStore{B: frameLog(t)}, &kernel.MemAnchor{})
	if err := cfg.Anchor.Put(kernel.SignHead(cfg.Sign, 0, kernel.Hash{})); err != nil {
		t.Fatal(err)
	}
	if l, err := kernel.Open(cfg); err != nil || l.Len() != 2 {
		t.Fatalf("a log under a head at seq 0: %v", err)
	}
}
