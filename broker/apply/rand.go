package apply

import (
	"crypto/rand"
	"math/big"
)

// cryptoRand returns a uniform number in [0, n), or 0 for n <= 0.
func cryptoRand(n int64) int64 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return n - 1 // fail late, never early
	}
	return v.Int64()
}
