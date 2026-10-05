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
	"fmt"
	"io"
	"strings"
)

// RecoveryKeyBytes is the recovery key's entropy: 160 bits. The key is
// never stretched (it is not chosen by a person), so its strength is its
// length; 160 bits is beyond offline search with no work factor at all.
const RecoveryKeyBytes = 20

// Alphabet is the Owner Card's alphabet for typed values (card.Alphabet,
// P2-2): 32 symbols, no I, O, 0 or 1.
const Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// The recovery key prints as 32 key symbols (160 bits) in eight groups of
// four, each group followed by one check symbol: 40 symbols in all.
const (
	keyGroups   = 8
	groupKeyLen = 4
	groupLen    = groupKeyLen + 1
	textSymbols = keyGroups * groupLen
)

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

// Text is the printed form: eight dash-separated groups of five symbols,
// four of the key and one check symbol (checkSymbol).
func (k RecoveryKey) Text() string {
	if k.b == nil {
		return ""
	}
	var syms []byte
	var acc uint64
	bits := 0
	for _, x := range k.b {
		acc = acc<<8 | uint64(x)
		bits += 8
		for bits >= 5 {
			bits -= 5
			syms = append(syms, byte((acc>>bits)&31))
		}
	}
	var s strings.Builder
	for g := 0; g < keyGroups; g++ {
		if g > 0 {
			s.WriteByte('-')
		}
		grp := syms[g*groupKeyLen : (g+1)*groupKeyLen]
		for _, v := range grp {
			s.WriteByte(Alphabet[v])
		}
		s.WriteByte(Alphabet[checkSymbol(grp)])
	}
	return s.String()
}

// checkSymbol is sum(a^(i+1) * s_i) over GF(32) (x^5 + x^2 + 1, a = x).
// Each position has a distinct nonzero weight, so any one wrong symbol and
// any swap of two different neighbours change it.
func checkSymbol(grp []byte) byte {
	var c, w byte = 0, 1
	for _, v := range grp {
		w = gfMul(w, 2)
		c ^= gfMul(w, v)
	}
	return c
}

func gfMul(a, b byte) byte {
	var p byte
	for b > 0 {
		if b&1 != 0 {
			p ^= a
		}
		b >>= 1
		a <<= 1
		if a&32 != 0 {
			a ^= 0x25 // x^5 + x^2 + 1
		}
	}
	return p
}

// String prints a placeholder, so a key logged by mistake shows nothing.
func (k RecoveryKey) String() string { return "[recovery key]" }

// GoString prints a placeholder.
func (k RecoveryKey) GoString() string { return "[recovery key]" }

// ErrRecoveryKeyFormat is text that is not 40 card symbols.
var ErrRecoveryKeyFormat = errors.New("recovery: that is not a recovery key; it has 40 letters and digits in groups of five")

// MistypedError is a key whose group fails its check symbol.
type MistypedError struct{ Group int }

func (e *MistypedError) Error() string {
	return fmt.Sprintf("recovery: group %d of the recovery key looks mistyped; check it against the card", e.Group)
}

// ParseRecoveryKey reads a typed or scanned key, ignoring case, spaces and
// dashes (card.Normalize). A group whose check symbol does not match is
// reported by number (MistypedError).
func ParseRecoveryKey(s string) (RecoveryKey, error) {
	var syms []byte
	for _, c := range strings.ToUpper(s) {
		if c == ' ' || c == '-' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		i := strings.IndexRune(Alphabet, c)
		if i < 0 || len(syms) == textSymbols {
			return RecoveryKey{}, ErrRecoveryKeyFormat
		}
		syms = append(syms, byte(i))
	}
	if len(syms) != textSymbols {
		return RecoveryKey{}, ErrRecoveryKeyFormat
	}
	var key []byte
	for g := 0; g < keyGroups; g++ {
		grp := syms[g*groupLen : g*groupLen+groupKeyLen]
		if checkSymbol(grp) != syms[g*groupLen+groupKeyLen] {
			return RecoveryKey{}, &MistypedError{Group: g + 1}
		}
		key = append(key, grp...)
	}
	var b [RecoveryKeyBytes]byte
	var acc uint64
	bits, n := 0, 0
	for _, v := range key {
		acc = acc<<5 | uint64(v)
		bits += 5
		if bits >= 8 {
			bits -= 8
			b[n] = byte(acc >> bits)
			n++
		}
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
