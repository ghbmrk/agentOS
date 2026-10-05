package card

import (
	"crypto/hmac"
	"crypto/sha256"
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

// recoveryKeyOK reports whether s is a recovery key whose every group
// passes its check symbol.
func recoveryKeyOK(s string) bool {
	n := Normalize(s)
	if len(n) != recoveryGroups*(recoveryGroupKey+1) {
		return false
	}
	for g := 0; g < recoveryGroups; g++ {
		grp := make([]byte, recoveryGroupKey+1)
		for i := range grp {
			k := strings.IndexByte(Alphabet, n[g*(recoveryGroupKey+1)+i])
			if k < 0 {
				return false
			}
			grp[i] = byte(k)
		}
		if checkSymbol(grp[:recoveryGroupKey]) != grp[recoveryGroupKey] {
			return false
		}
	}
	return true
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
