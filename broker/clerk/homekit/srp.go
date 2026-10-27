package homekit

import (
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"math/big"
)

// SRP-6a as HAP uses it: RFC 5054's 3072-bit group (g = 5), SHA-512, user
// "Pair-Setup", and fixed-width encodings: PAD() is 384 bytes for A, B and S.
// It is the one hand-written primitive; testdata/srp_vectors.json pins it.

const srpLen = 384

var (
	srpN = mustHex("" +
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
		"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
		"302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
		"A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
		"FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
		"180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
		"3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D" +
		"04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D" +
		"B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226" +
		"1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC" +
		"E0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF")
	srpG    = big.NewInt(5)
	srpK    = new(big.Int).SetBytes(srpHash(srpPad(srpN), srpPad(srpG)))
	srpUser = []byte("Pair-Setup")
	// H(N) xor H(g), with g as its one byte.
	srpHGroup = func() []byte {
		hn, hg := srpHash(srpPad(srpN)), srpHash([]byte{5})
		for i := range hn {
			hn[i] ^= hg[i]
		}
		return hn
	}()
)

func mustHex(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("homekit: bad constant")
	}
	return n
}

func srpHash(parts ...[]byte) []byte {
	h := sha512.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func srpPad(n *big.Int) []byte { return n.FillBytes(make([]byte, srpLen)) }

// srpResult is the controller's side of one exchange.
type srpResult struct {
	A, M1, K []byte
	m2       []byte // the server proof the accessory must send
}

// checkM2 compares the accessory's proof in constant time.
func (r *srpResult) checkM2(m2 []byte) bool { return subtle.ConstantTimeCompare(r.m2, m2) == 1 }

// srpClient runs the controller's computation for setup code, salt and the
// accessory's B, with private value a. It refuses a salt that is not 16
// bytes, a B that is longer than the group or zero modulo N, and u = 0.
func srpClient(code string, salt, bBytes []byte, a *big.Int) (*srpResult, error) {
	if len(salt) != 16 {
		return nil, fmt.Errorf("%w: srp salt of %d bytes", ErrProtocol, len(salt))
	}
	if len(bBytes) == 0 || len(bBytes) > srpLen {
		return nil, fmt.Errorf("%w: srp B of %d bytes", ErrProtocol, len(bBytes))
	}
	B := new(big.Int).SetBytes(bBytes)
	if new(big.Int).Mod(B, srpN).Sign() == 0 {
		return nil, fmt.Errorf("%w: srp B is zero modulo N", ErrAuthentication)
	}
	A := new(big.Int).Exp(srpG, a, srpN)
	pA, pB := srpPad(A), srpPad(B)
	u := new(big.Int).SetBytes(srpHash(pA, pB))
	if u.Sign() == 0 {
		return nil, fmt.Errorf("%w: srp u is zero", ErrAuthentication)
	}
	x := new(big.Int).SetBytes(srpHash(salt, srpHash(srpUser, []byte(":"), []byte(code))))
	v := new(big.Int).Exp(srpG, x, srpN)
	// S = (B - k*v) ^ (a + u*x) mod N
	base := new(big.Int).Mul(srpK, v)
	base.Sub(B, base).Mod(base, srpN)
	exp := new(big.Int).Mul(u, x)
	exp.Add(exp, a)
	S := new(big.Int).Exp(base, exp, srpN)
	K := srpHash(srpPad(S))
	M1 := srpHash(srpHGroup, srpHash(srpUser), salt, pA, pB, K)
	return &srpResult{A: pA, M1: M1, K: K, m2: srpHash(pA, M1, K)}, nil
}

// normalizeCode accepts "XXX-XX-XXX" or eight digits and returns the dashed
// form HAP hashes.
func normalizeCode(code string) (string, error) {
	d := make([]byte, 0, 8)
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c >= '0' && c <= '9':
			d = append(d, c)
		case c == '-' && (i == 3 || i == 6) && len(code) == 10:
		default:
			return "", fmt.Errorf("%w: a HomeKit code is eight digits", ErrRefused)
		}
	}
	if len(d) != 8 {
		return "", fmt.Errorf("%w: a HomeKit code is eight digits", ErrRefused)
	}
	return string(d[:3]) + "-" + string(d[3:5]) + "-" + string(d[5:]), nil
}
