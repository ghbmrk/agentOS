package camera

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// NewClientKey makes the core's camera client key, a P-256 key, and hands
// its 32-byte scalar to put, which seals it into a device slot
// (clerk.Secrets.Put under DeviceSlots). The scalar is wiped after put
// returns (CLK-1).
func NewClientKey(put func(raw []byte) error) error {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	raw, err := k.Bytes()
	if err != nil {
		return err
	}
	defer clear(raw)
	return put(raw)
}

// ClientKey is the core's camera client key over the sealed store (design
// point 1, CLK-1, A16). It keeps no private key: each signature lends the
// scalar for one call (clerk.Secrets.DeviceKey), signs and drops it. It
// keeps only the public key and a self-signed certificate over it, which
// the node checks against its bundle's core key (camwire.Bundle.Core).
type ClientKey struct {
	lend func(fn func(raw []byte) error) error
	pub  *ecdsa.PublicKey
	cert tls.Certificate
}

var errKey = errors.New("camera: client key slot holds no P-256 key")

// OpenClientKey derives the public key and certificate from the slot lend
// opens.
func OpenClientKey(lend func(fn func(raw []byte) error) error) (*ClientKey, error) {
	k := &ClientKey{lend: lend}
	if err := lend(func(raw []byte) error {
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
		if err != nil {
			return errKey
		}
		k.pub = &priv.PublicKey
		return nil
	}); err != nil {
		return nil, errKey
	}
	// The node checks the key alone; the certificate's fields are fixed.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agentos camera client"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.pub, k)
	if err != nil {
		return nil, errKey
	}
	k.cert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
	return k, nil
}

// Format prints no field, whatever the verb.
func (k *ClientKey) Format(f fmt.State, _ rune) { fmt.Fprint(f, "camera.ClientKey{}") }

// Point is the key's uncompressed point, for the node's bundle (the owner
// signs it in as camwire.Bundle.Core).
func (k *ClientKey) Point() [camwire.PointLen]byte {
	var p [camwire.PointLen]byte
	b, _ := k.pub.Bytes()
	copy(p[:], b)
	return p
}

// Public is the crypto.Signer's public key.
func (k *ClientKey) Public() crypto.PublicKey { return k.pub }

// Sign lends the scalar for one signature. The lent bytes are the store's
// to wipe; the parsed key goes out of reach when Sign returns.
func (k *ClientKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var sig []byte
	err := k.lend(func(raw []byte) error {
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
		if err != nil {
			return errKey
		}
		if !priv.PublicKey.Equal(k.pub) {
			return errKey
		}
		sig, err = priv.Sign(r, digest, opts)
		return err
	})
	if err != nil {
		return nil, errKey
	}
	return sig, nil
}

func (k *ClientKey) certificate() *tls.Certificate { return &k.cert }
