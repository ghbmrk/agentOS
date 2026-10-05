// Package recovery restores a box onto new hardware and replaces lost or
// exposed owner factors (SPEC §7.5, REC-1 to REC-4; A8).
//
// It handles the vault's data key only as bytes wrapped by key slots and
// never reads a vault value, so it does not import the vault package. The
// process that holds the unlocked data key (the vault process) calls it.
package recovery

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
)

// RecoveryKeyBytes is the recovery key's entropy: 160 bits. The key is
// never stretched (it is not chosen by a person), so its strength is its
// length; 160 bits is beyond offline search with no work factor at all.
const RecoveryKeyBytes = 20

// Alphabet is the Owner Card's alphabet for typed values (card.Alphabet,
// P2-2): 32 symbols, no I, O, 0 or 1. The recovery key prints as 32 of
// them, 160 bits, in groups of four.
const Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// RecoveryKey is the secret printed on the Owner Card's recovery sheet
// (ID-1). It formats as a placeholder; only Text returns the printable form.
type RecoveryKey struct{ b *[RecoveryKeyBytes]byte }

// NewRecoveryKey draws a fresh key from r (crypto/rand when nil).
func NewRecoveryKey(r io.Reader) (RecoveryKey, error) {
	if r == nil {
		r = rand.Reader
	}
	var b [RecoveryKeyBytes]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return RecoveryKey{}, err
	}
	return RecoveryKey{b: &b}, nil
}

// Valid reports whether k holds a key.
func (k RecoveryKey) Valid() bool { return k.b != nil }

// Text is the printed form: 32 symbols in eight groups of four, the format
// of card.Card.RecoveryKey.
func (k RecoveryKey) Text() string {
	if k.b == nil {
		return ""
	}
	var s strings.Builder
	var acc uint64
	bits := 0
	for _, x := range k.b {
		acc = acc<<8 | uint64(x)
		bits += 8
		for bits >= 5 {
			bits -= 5
			if s.Len()%5 == 4 {
				s.WriteByte('-')
			}
			s.WriteByte(Alphabet[(acc>>bits)&31])
		}
	}
	return s.String()
}

// String prints a placeholder, so a key logged by mistake shows nothing.
func (k RecoveryKey) String() string { return "[recovery key]" }

// GoString prints a placeholder.
func (k RecoveryKey) GoString() string { return "[recovery key]" }

// ErrRecoveryKeyFormat is text that is not 32 card symbols.
var ErrRecoveryKeyFormat = errors.New("recovery: that is not a recovery key; it has 32 letters and digits in groups of four")

// ParseRecoveryKey reads a typed or scanned key, ignoring case, spaces and
// dashes (card.Normalize). A key with a typo parses but opens no slot.
func ParseRecoveryKey(s string) (RecoveryKey, error) {
	var b [RecoveryKeyBytes]byte
	var acc uint64
	bits, n, syms := 0, 0, 0
	for _, c := range strings.ToUpper(s) {
		if c == ' ' || c == '-' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		i := strings.IndexRune(Alphabet, c)
		if i < 0 || syms == 32 {
			return RecoveryKey{}, ErrRecoveryKeyFormat
		}
		syms++
		acc = acc<<5 | uint64(i)
		bits += 5
		if bits >= 8 {
			bits -= 8
			b[n] = byte(acc >> bits)
			n++
		}
	}
	if syms != 32 {
		return RecoveryKey{}, ErrRecoveryKeyFormat
	}
	return RecoveryKey{b: &b}, nil
}

// Wipe zeroes the key.
func (k RecoveryKey) Wipe() {
	if k.b != nil {
		for i := range k.b {
			k.b[i] = 0
		}
	}
}

// hkdf is RFC 5869 HKDF-SHA256 (the standard library's crypto/hkdf needs a
// newer Go than go.mod states).
func hkdf(secret, salt []byte, info string, n int) []byte {
	ext := hmac.New(sha256.New, salt)
	ext.Write(secret)
	prk := ext.Sum(nil)
	var out, prev []byte
	for i := byte(1); len(out) < n; i++ {
		m := hmac.New(sha256.New, prk)
		m.Write(prev)
		m.Write([]byte(info))
		m.Write([]byte{i})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}

func newGCM(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func random(r io.Reader, n int) ([]byte, error) {
	if r == nil {
		r = rand.Reader
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
