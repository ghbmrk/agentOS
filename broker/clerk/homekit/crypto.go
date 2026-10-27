package homekit

import (
	"crypto/hkdf"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// hkdfKey is HAP's HKDF-SHA-512 with a 32-byte output.
func hkdfKey(secret []byte, salt, info string) []byte {
	k, err := hkdf.Key(sha512.New, secret, []byte(salt), info, 32)
	if err != nil {
		panic(err) // only on an invalid length, which is fixed here
	}
	return k
}

// msgNonce is HAP's pairing nonce: four zero bytes and an 8-byte label.
func msgNonce(label string) []byte { return append(make([]byte, 4), label...) }

func sealMsg(key []byte, label string, plain []byte) []byte {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, msgNonce(label), plain, nil)
}

func openMsg(key []byte, label string, ct []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	p, err := aead.Open(nil, msgNonce(label), ct, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s does not authenticate", ErrAuthentication, label)
	}
	return p, nil
}
