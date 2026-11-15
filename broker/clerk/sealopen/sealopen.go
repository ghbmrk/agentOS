// Package sealopen opens a sealed value for one call and wipes the
// plaintext on every path (CLK-1, STO-2). A sealer may fail after it
// decrypted and hand the plaintext back beside its error, so a caller that
// returns on that error before its wipe leaves a credential or a private
// record in memory (#5666, #5772, #5784). The clerk's stores open through
// With, so the wipe is written once, here, and held by this package's tests;
// broker/clerk/wipelint holds the shape of every other sealer Open.
package sealopen

// Opener is a sealer's Open (clerk.Sealer's).
type Opener interface {
	Open(blob, aad []byte) ([]byte, error)
}

// With opens blob under aad with s and, if it opens, calls fn with the
// plaintext. The plaintext is wiped when With returns, on every path, the
// failing Open included, so fn must not keep it. It returns Open's error
// unchanged, or fn's.
func With(s Opener, blob, aad []byte, fn func(plain []byte) error) error {
	plain, err := s.Open(blob, aad)
	defer clear(plain)
	if err != nil {
		return err
	}
	return fn(plain)
}
