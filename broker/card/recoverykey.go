package card

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
)

// The recovery key's printed format, shared with broker/recovery (P2-8):
// 160 bits as 32 symbols in eight groups of four, each group followed by
// one check symbol, so a typo names its group. 40 symbols in all.
const (
	recoveryKeyBytes = 20
	recoveryGroups   = 8
	recoveryGroupKey = 4
)

// RecoveryKeyText prints a 20-byte recovery key in the card format.
func RecoveryKeyText(b [recoveryKeyBytes]byte) string {
	var syms []byte
	var acc uint64
	bits := 0
	for _, x := range b {
		acc = acc<<8 | uint64(x)
		bits += 8
		for bits >= 5 {
			bits -= 5
			syms = append(syms, byte((acc>>bits)&31))
		}
	}
	var s strings.Builder
	for g := 0; g < recoveryGroups; g++ {
		if g > 0 {
			s.WriteByte('-')
		}
		grp := syms[g*recoveryGroupKey : (g+1)*recoveryGroupKey]
		for _, v := range grp {
			s.WriteByte(Alphabet[v])
		}
		s.WriteByte(Alphabet[checkSymbol(grp)])
	}
	return s.String()
}

// StoreKeyLen is the length of the key the sealed store's recovery slot
// and the backups' recipient take (seal.RecoveryLen, backup.RecipientFor).
const StoreKeyLen = 32

// ErrRecoveryKey: the text is not a card recovery key, or a group fails
// its check symbol. A mistyped group is a *MistypedError, which is also
// ErrRecoveryKey (errors.Is).
var ErrRecoveryKey = errors.New("card: not a recovery key, or a group is mistyped")

// MistypedError is a recovery key of the right length whose group Group
// (1 to 8, as printed) fails its check symbol or holds a symbol the card
// never prints, so the restore and rotation pages can say which group to
// retype (REC-1, REC-4).
type MistypedError struct{ Group int }

func (e *MistypedError) Error() string {
	return fmt.Sprintf("card: group %d of the recovery key looks mistyped; check it against the card", e.Group)
}

// Is makes every MistypedError an ErrRecoveryKey.
func (e *MistypedError) Is(target error) bool { return target == ErrRecoveryKey }

// StoreRecoveryKey reads a typed or printed recovery key and returns the
// StoreKeyLen-byte key the sealed store's recovery slot and the backups
// are sealed to (MIG-4-recovery-len, #3406): HKDF-SHA256 of the card's 160
// bits, info "agentos.card.store-recovery.v1". The card keeps its 40
// symbols, so every card already printed opens the slot; the slot keeps
// its 32 bytes, at the card's 160 bits of strength. A refusal is
// ErrRecoveryKey, or a *MistypedError naming the group. The caller owns
// the returned slice and must clear it once the slot or backup is open;
// the card's 160 bits are cleared here. s itself is a Go string and
// cannot be wiped (ASSUMPTIONS C13).
func StoreRecoveryKey(s string) ([]byte, error) {
	b, err := parseRecoveryKey(s)
	if err != nil {
		return nil, err
	}
	k, err := hkdf.Key(sha256.New, b[:], nil, "agentos.card.store-recovery.v1", StoreKeyLen)
	clear(b[:])
	if err != nil {
		return nil, err
	}
	return k, nil
}

// recoveryKeyOK reports whether s is a recovery key whose every group
// passes its check symbol.
func recoveryKeyOK(s string) bool {
	b, err := parseRecoveryKey(s)
	clear(b[:])
	return err == nil
}

// parseRecoveryKey is RecoveryKeyText's inverse, after Normalize. Text of
// the wrong length is ErrRecoveryKey; a group with a bad symbol or check
// is a *MistypedError. The per-group symbols live in one stack array,
// cleared with the bit accumulator before return.
func parseRecoveryKey(s string) (b [recoveryKeyBytes]byte, err error) {
	n := Normalize(s)
	if len(n) != recoveryGroups*(recoveryGroupKey+1) {
		return b, ErrRecoveryKey
	}
	var grp [recoveryGroupKey + 1]byte
	var acc uint64
	defer func() { clear(grp[:]); acc = 0 }()
	bits, j := 0, 0
	for g := 0; g < recoveryGroups; g++ {
		for i := range grp {
			k := strings.IndexByte(Alphabet, n[g*(recoveryGroupKey+1)+i])
			if k < 0 {
				clear(b[:])
				return b, &MistypedError{Group: g + 1}
			}
			grp[i] = byte(k)
		}
		if checkSymbol(grp[:recoveryGroupKey]) != grp[recoveryGroupKey] {
			clear(b[:])
			return b, &MistypedError{Group: g + 1}
		}
		for _, v := range grp[:recoveryGroupKey] {
			acc = acc<<5 | uint64(v)
			bits += 5
			if bits >= 8 {
				bits -= 8
				b[j] = byte(acc >> bits)
				j++
			}
		}
	}
	return b, nil
}

// checkSymbol is sum(a^(i+1) * s_i) over GF(32) (x^5 + x^2 + 1, a = x):
// any one wrong symbol, and any swap of two different neighbours, changes
// it.
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
			a ^= 0x25
		}
	}
	return p
}

// GridCheck is the four-symbol code printed under the grid, so a grid-only
// rotation can be confirmed from the printed card (P2-8): HKDF-SHA256 of
// the grid seed, info "agentos-grid-check-v1", each byte's low 5 bits.
func GridCheck(seed []byte) string {
	prk := hmac.New(sha256.New, nil)
	prk.Write(seed)
	m := hmac.New(sha256.New, prk.Sum(nil))
	m.Write([]byte("agentos-grid-check-v1"))
	m.Write([]byte{1})
	k := m.Sum(nil)[:4]
	out := make([]byte, 4)
	for i, x := range k {
		out[i] = Alphabet[x&31]
	}
	return string(out)
}
