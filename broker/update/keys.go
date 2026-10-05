package update

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// Keys are Ed25519. A private key is a PKCS #8 PEM file, mode 0600, meant
// to live on an offline machine or drive (UPD-2); its public half is a
// PKIX PEM file beside it.

// Keygen writes base+".key" and base+".pub". It refuses to overwrite.
func Keygen(base string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pder, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if err := writeNew(base+".key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	if err := writeNew(base+".pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pder}), 0o644); err != nil {
		os.Remove(base + ".key")
		return nil, err
	}
	return pub, nil
}

func writeNew(name string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(name)
		return err
	}
	return f.Close()
}

func readPEM(name, typ string) ([]byte, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != typ {
		return nil, fmt.Errorf("%s: not a %s PEM file", name, typ)
	}
	return blk.Bytes, nil
}

// LoadPublicKey reads an Ed25519 public key file.
func LoadPublicKey(name string) (ed25519.PublicKey, error) {
	der, err := readPEM(name, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", name)
	}
	return pub, nil
}

// LoadPrivateKey reads an Ed25519 private key file.
func LoadPrivateKey(name string) (ed25519.PrivateKey, error) {
	der, err := readPEM(name, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an Ed25519 key", name)
	}
	return priv, nil
}

// Signer wraps a private key for metadata signing.
func Signer(priv ed25519.PrivateKey) (signature.Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("not an Ed25519 private key")
	}
	return signature.LoadED25519Signer(priv)
}

// KeyID is the TUF key ID of a public key.
func KeyID(pub crypto.PublicKey) (string, error) {
	k, err := metadata.KeyFromPublicKey(pub)
	if err != nil {
		return "", err
	}
	return k.ID()
}
