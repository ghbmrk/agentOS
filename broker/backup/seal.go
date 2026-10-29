// Package backup seals a backup so that opening it needs both an X25519 and
// an ML-KEM-768 secret, each derived from the owner's recovery key (BAK-1,
// D-149), and re-seals an older backup's subject-key table without an erased
// subject (D-168). It is a library: the box keeps only the public Recipient
// and never the recovery key, and only a restore sees the recovery key.
// Decisions and residual risks: briefs/MIG-4-recovery-a.md and ASSUMPTIONS.md.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Object kinds: a backup is one content object and one key-table object.
const (
	KindContent  = "content"
	KindKeyTable = "keytable"
)

const (
	magic     = "AGOSBAK1"
	version   = 2
	idLen     = 16
	chunkSize = 64 << 10
	tagSize   = 16
	// headerLen is magic, version, kind, backup ID, generation, the
	// ephemeral X25519 key and the ML-KEM ciphertext. It names no
	// recipient (#3446): a recipient ID in the clear would let one guess at
	// the recovery key be checked against every install's uploads by one
	// lookup, where without it each object costs its own key agreement.
	// Version 1 had the ID after the generation; it is refused.
	headerLen = len(magic) + 1 + 1 + idLen + 8 + 32 + mlkem.CiphertextSize768
	// minRK is the shortest recovery key accepted; the card's is 20 bytes.
	minRK = 16
)

var (
	ErrShortKey = errors.New("backup: a recovery key is at least 16 bytes")
	ErrHeader   = errors.New("backup: not a backup object of the expected kind and version")
	ErrOpen     = errors.New("backup: the object does not open: sealed to another recovery key, or changed, truncated, reordered or extended")
)

var kindCode = map[string]byte{KindContent: 1, KindKeyTable: 2}

// Recipient is the public half of the backup key pair a recovery key
// derives. Setup and every recovery-key rotation store it; it holds no
// private byte.
type Recipient struct {
	X  []byte `json:"x"`  // X25519 public key, 32 bytes
	EK []byte `json:"ek"` // ML-KEM-768 encapsulation key, 1184 bytes
}

// ID names the recipient: the first 16 bytes of SHA-256 over both keys, hex.
// It is for the box's own records and the sealed manifest, never an
// object's clear header (#3446).
func (r Recipient) ID() string { id := r.id(); return hex.EncodeToString(id[:]) }

func (r Recipient) id() [idLen]byte {
	h := sha256.New()
	h.Write(r.X)
	h.Write(r.EK)
	var id [idLen]byte
	copy(id[:], h.Sum(nil))
	return id
}

func (r Recipient) keys() (*ecdh.PublicKey, *mlkem.EncapsulationKey768, error) {
	x, err := ecdh.X25519().NewPublicKey(r.X)
	if err != nil {
		return nil, nil, fmt.Errorf("backup: recipient X25519 key: %w", err)
	}
	ek, err := mlkem.NewEncapsulationKey768(r.EK)
	if err != nil {
		return nil, nil, fmt.Errorf("backup: recipient ML-KEM key: %w", err)
	}
	return x, ek, nil
}

// privateHalves derives the X25519 private key and the ML-KEM-768
// decapsulation key from the recovery key.
func privateHalves(rk []byte) (*ecdh.PrivateKey, *mlkem.DecapsulationKey768, error) {
	if len(rk) < minRK {
		return nil, nil, ErrShortKey
	}
	xs, err := hkdf.Key(sha256.New, rk, nil, "agentos.backup.x25519.v1", 32)
	if err != nil {
		return nil, nil, err
	}
	// Both constructors copy their input, so the derived bytes are wiped
	// here (best-effort, as handoff.KernelKeys.Wipe; #3274).
	defer clear(xs)
	x, err := ecdh.X25519().NewPrivateKey(xs)
	if err != nil {
		return nil, nil, err
	}
	seed, err := hkdf.Key(sha256.New, rk, nil, "agentos.backup.mlkem768.v1", mlkem.SeedSize)
	if err != nil {
		return nil, nil, err
	}
	defer clear(seed)
	dk, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return nil, nil, err
	}
	return x, dk, nil
}

// RecipientFor derives the public Recipient of a recovery key.
func RecipientFor(rk []byte) (Recipient, error) {
	x, dk, err := privateHalves(rk)
	if err != nil {
		return Recipient{}, err
	}
	return Recipient{X: x.PublicKey().Bytes(), EK: dk.EncapsulationKey().Bytes()}, nil
}

// header is an object's clear header, the AAD of every chunk.
type header struct {
	kind     string
	backupID [idLen]byte
	gen      uint64
	eph      [32]byte
	ctM      [mlkem.CiphertextSize768]byte
}

func (h *header) encode() []byte {
	b := make([]byte, 0, headerLen)
	b = append(b, magic...)
	b = append(b, version, kindCode[h.kind])
	b = append(b, h.backupID[:]...)
	b = binary.BigEndian.AppendUint64(b, h.gen)
	b = append(b, h.eph[:]...)
	return append(b, h.ctM[:]...)
}

func parseHeader(b []byte) (header, error) {
	var h header
	if len(b) != headerLen || string(b[:len(magic)]) != magic || b[len(magic)] != version {
		return h, ErrHeader
	}
	b = b[len(magic)+1:]
	for k, c := range kindCode {
		if b[0] == c {
			h.kind = k
		}
	}
	if h.kind == "" {
		return h, ErrHeader
	}
	b = b[1:]
	b = b[copy(h.backupID[:], b):]
	h.gen, b = binary.BigEndian.Uint64(b), b[8:]
	b = b[copy(h.eph[:], b):]
	copy(h.ctM[:], b)
	return h, nil
}

// combine is the X-Wing-style combiner: both shared secrets are the HKDF
// input, and both ciphertexts and both public keys are in its info, so a
// swapped or dropped half changes the key.
func combine(ssM, ssX []byte, kind string, ctM, ephPub, rX, ek []byte) ([]byte, error) {
	ekHash := sha256.Sum256(ek)
	info := make([]byte, 0, 256+len(ctM))
	info = append(info, "agentos.backup.seal.v1"...)
	info = append(info, kind...)
	info = append(info, ctM...)
	info = append(info, ephPub...)
	info = append(info, rX...)
	info = append(info, ekHash[:]...)
	return hkdf.Key(sha256.New, append(bytes.Clone(ssM), ssX...), nil, string(info), 32)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// nonce is the STREAM nonce: an 88-bit chunk counter, then 1 on the last
// chunk only.
func nonce(i uint64, last bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[3:11], i)
	if last {
		n[11] = 1
	}
	return n
}

// sealer writes one object: the header, then the body in STREAM chunks.
// The last chunk is sealed at Close, so a body that ends on a chunk
// boundary still has a flagged last chunk, and an empty body is one empty
// last chunk.
type sealer struct {
	w    io.Writer
	aead cipher.AEAD
	aad  []byte
	buf  []byte
	i    uint64
	done bool
}

// sealTo writes h's header to w, sealed to r, and returns the body writer.
// h.eph and h.ctM are filled here.
func sealTo(w io.Writer, r Recipient, h header) (io.WriteCloser, error) {
	rx, ek, err := r.keys()
	if err != nil {
		return nil, err
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ssX, err := eph.ECDH(rx)
	if err != nil {
		return nil, err
	}
	ssM, ctM := ek.Encapsulate()
	copy(h.eph[:], eph.PublicKey().Bytes())
	copy(h.ctM[:], ctM)
	key, err := combine(ssM, ssX, h.kind, ctM, h.eph[:], r.X, r.EK)
	if err != nil {
		return nil, err
	}
	a, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	aad := h.encode()
	if _, err := w.Write(aad); err != nil {
		return nil, err
	}
	return &sealer{w: w, aead: a, aad: aad, buf: make([]byte, 0, chunkSize)}, nil
}

func (s *sealer) Write(p []byte) (int, error) {
	if s.done {
		return 0, errors.New("backup: write after close")
	}
	n := 0
	for len(p) > 0 {
		if len(s.buf) == chunkSize {
			if err := s.flush(false); err != nil {
				return n, err
			}
		}
		c := copy(s.buf[len(s.buf):chunkSize], p)
		s.buf = s.buf[:len(s.buf)+c]
		p, n = p[c:], n+c
	}
	return n, nil
}

func (s *sealer) flush(last bool) error {
	ct := s.aead.Seal(nil, nonce(s.i, last), s.buf, s.aad)
	s.i++
	s.buf = s.buf[:0]
	_, err := s.w.Write(ct)
	return err
}

func (s *sealer) Close() error {
	if s.done {
		return nil
	}
	s.done = true
	return s.flush(true)
}

// opener reads an object's body chunk by chunk; nothing of a chunk is
// returned before its tag checks. The last chunk is the one that ends the
// stream, so a cut or an extra chunk fails its tag.
type opener struct {
	r    io.Reader
	aead cipher.AEAD
	aad  []byte
	i    uint64
	buf  []byte // a sealed chunk and one byte past it
	n    int    // bytes of buf filled
	out  []byte // plaintext not yet returned
	last bool
}

// openFrom reads an object's header, refuses another kind, and checks the
// first chunk before returning, so a changed header byte or another
// recovery key fails here (ErrOpen). It returns the recipient rk derives.
func openFrom(r io.Reader, rk []byte, kind string) (header, Recipient, io.Reader, error) {
	hb := make([]byte, headerLen)
	if _, err := io.ReadFull(r, hb); err != nil {
		return header{}, Recipient{}, nil, ErrHeader
	}
	h, err := parseHeader(hb)
	if err != nil {
		return header{}, Recipient{}, nil, err
	}
	if h.kind != kind {
		return header{}, Recipient{}, nil, ErrHeader
	}
	x, dk, err := privateHalves(rk)
	if err != nil {
		return header{}, Recipient{}, nil, err
	}
	rcp := Recipient{X: x.PublicKey().Bytes(), EK: dk.EncapsulationKey().Bytes()}
	ephPub, err := ecdh.X25519().NewPublicKey(h.eph[:])
	if err != nil {
		return header{}, Recipient{}, nil, ErrOpen
	}
	ssX, err := x.ECDH(ephPub)
	if err != nil {
		return header{}, Recipient{}, nil, ErrOpen
	}
	ssM, err := dk.Decapsulate(h.ctM[:])
	if err != nil {
		return header{}, Recipient{}, nil, ErrOpen
	}
	key, err := combine(ssM, ssX, kind, h.ctM[:], h.eph[:], rcp.X, rcp.EK)
	if err != nil {
		return header{}, Recipient{}, nil, err
	}
	a, err := newGCM(key)
	if err != nil {
		return header{}, Recipient{}, nil, err
	}
	o := &opener{r: r, aead: a, aad: hb, buf: make([]byte, chunkSize+tagSize+1)}
	if err := o.next(); err != nil {
		return header{}, Recipient{}, nil, err
	}
	return h, rcp, o, nil
}

// next opens the following chunk. It reads one byte past a full chunk to
// learn whether the chunk is the last.
func (o *opener) next() error {
	m, err := io.ReadFull(o.r, o.buf[o.n:])
	o.n += m
	sealed, last := o.buf[:o.n], true
	switch {
	case err == nil:
		sealed, last = o.buf[:chunkSize+tagSize], false
	case !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF):
		return err
	}
	pt, err := o.aead.Open(nil, nonce(o.i, last), sealed, o.aad)
	if err != nil {
		return ErrOpen
	}
	o.out, o.last, o.i = pt, last, o.i+1
	if last {
		o.n = 0
	} else {
		o.buf[0], o.n = o.buf[chunkSize+tagSize], 1
	}
	return nil
}

func (o *opener) Read(p []byte) (int, error) {
	for len(o.out) == 0 {
		if o.last {
			return 0, io.EOF
		}
		if err := o.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, o.out)
	o.out = o.out[n:]
	return n, nil
}
