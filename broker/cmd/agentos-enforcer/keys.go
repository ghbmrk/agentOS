package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/page"
)

var errKeyFile = errors.New("key file unreadable")

// channelKey is the enforcer's Ed25519 channel key, made on first start
// and kept in the state directory (mode 0600). Its public half is what the
// kernel pins (slice o).
func channelKey(store fileStore, r io.Reader) (ed25519.PrivateKey, error) {
	b, err := store.Load()
	if err != nil {
		return nil, err
	}
	if b == nil {
		_, priv, err := ed25519.GenerateKey(r)
		if err != nil {
			return nil, err
		}
		if err := store.Save([]byte(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n")); err != nil {
			return nil, err
		}
		return priv, nil
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errKeyFile
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// coreKey is the kernel's channel sub-key, pinned when the core was set up
// beside the enforcer (ASSUMPTIONS ENF-l-6): base64 of the 32 bytes. With
// none pinned, the enforcer runs no channel at all.
func coreKey(store fileStore) (ed25519.PublicKey, error) {
	b, err := store.Load()
	if err != nil || b == nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != ed25519.PublicKeySize {
		return nil, errKeyFile
	}
	return ed25519.PublicKey(k), nil
}

// certFile is page.Cert as the state directory keeps it.
type certFile struct {
	Root    []byte   `json:"root"`
	RootKey []byte   `json:"root_key"` // PKCS #8
	Leaf    [][]byte `json:"leaf"`
	LeafKey []byte   `json:"leaf_key"` // PKCS #8
}

// pageCert is the page's TLS identity: loaded, or made and kept on first
// start, and renewed when its leaf is near its end. The root never
// changes, so the owner's phone keeps trusting the page.
func pageCert(store fileStore, name string, now time.Time) (page.Cert, error) {
	b, err := store.Load()
	if err != nil {
		return page.Cert{}, err
	}
	var c page.Cert
	if b == nil {
		if c, err = page.NewCert(name, now); err != nil {
			return page.Cert{}, err
		}
	} else if c, err = decodeCert(b); err != nil {
		return page.Cert{}, err
	}
	r, err := c.Renew(name, now)
	if err != nil {
		return page.Cert{}, err
	}
	if b == nil || !leafEqual(r, c) {
		if err := saveCert(store, r); err != nil {
			return page.Cert{}, err
		}
	}
	return r, nil
}

func leafEqual(a, b page.Cert) bool {
	return len(a.Leaf.Certificate) > 0 && len(b.Leaf.Certificate) > 0 && string(a.Leaf.Certificate[0]) == string(b.Leaf.Certificate[0])
}

func saveCert(store fileStore, c page.Cert) error {
	rk, err := x509.MarshalPKCS8PrivateKey(c.RootKey)
	if err != nil {
		return err
	}
	lk, err := x509.MarshalPKCS8PrivateKey(c.Leaf.PrivateKey)
	if err != nil {
		return err
	}
	b, _ := json.Marshal(certFile{Root: c.Root, RootKey: rk, Leaf: c.Leaf.Certificate, LeafKey: lk}) // byte slices only
	return store.Save(b)
}

func decodeCert(b []byte) (page.Cert, error) {
	var f certFile
	if err := json.Unmarshal(b, &f); err != nil || len(f.Leaf) == 0 {
		return page.Cert{}, errKeyFile
	}
	rk, err := x509.ParsePKCS8PrivateKey(f.RootKey)
	if err != nil {
		return page.Cert{}, errKeyFile
	}
	lk, err := x509.ParsePKCS8PrivateKey(f.LeafKey)
	if err != nil {
		return page.Cert{}, errKeyFile
	}
	rs, ok1 := rk.(crypto.Signer)
	ls, ok2 := lk.(crypto.Signer)
	if !ok1 || !ok2 {
		return page.Cert{}, errKeyFile
	}
	if _, err := x509.ParseCertificate(f.Root); err != nil {
		return page.Cert{}, errKeyFile
	}
	return page.Cert{Root: f.Root, RootKey: rs, Leaf: tls.Certificate{Certificate: f.Leaf, PrivateKey: ls}}, nil
}
