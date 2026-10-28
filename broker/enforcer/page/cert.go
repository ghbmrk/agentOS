package page

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// RootLife is how long the root lasts; LeafLife how long each page
// certificate lasts, inside Apple's 825-day cap for TLS server
// certificates, which holds even under an owner-installed root. Renew
// issues a new leaf once the old one has less than RenewBefore left.
const (
	RootLife    = 10 * 365 * 24 * time.Hour
	LeafLife    = 397 * 24 * time.Hour
	RenewBefore = 30 * 24 * time.Hour
)

// Cert is the page's TLS identity (NET-4 Passkey rules): a root the owner's
// phone may trust that is limited, by a critical name constraint, to the
// enforcer's own local name, and the page's certificate under it. A root
// that leaked could vouch for no other site.
type Cert struct {
	Root    []byte // DER, for the phone to install
	RootKey crypto.Signer
	Leaf    tls.Certificate
}

// NewCert makes a fresh Cert for name. The daemon keeps it in the
// enforcer's sealed store (slice l).
func NewCert(name string, now time.Time) (Cert, error) {
	root, rootKey, err := newRoot(name, now)
	if err != nil {
		return Cert{}, err
	}
	leaf, err := issue(root, rootKey, name, now)
	if err != nil {
		return Cert{}, err
	}
	return Cert{Root: root.Raw, RootKey: rootKey, Leaf: leaf}, nil
}

// Renew is c with a fresh leaf for name if the current one has less than
// RenewBefore left at now, and c unchanged otherwise. The root stays, so
// the phone keeps trusting the page. The daemon calls it daily (slice l).
func (c Cert) Renew(name string, now time.Time) (Cert, error) {
	leaf, err := x509.ParseCertificate(c.Leaf.Certificate[0])
	if err != nil {
		return c, err
	}
	if leaf.NotAfter.Sub(now) >= RenewBefore {
		return c, nil
	}
	root, err := x509.ParseCertificate(c.Root)
	if err != nil {
		return c, err
	}
	l, err := issue(root, c.RootKey, name, now)
	if err != nil {
		return c, err
	}
	c.Leaf = l
	return c, nil
}

func newRoot(name string, now time.Time) (*x509.Certificate, crypto.Signer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	t := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: name + " enforcer root"},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.Add(RootLife),
		KeyUsage:                    x509.KeyUsageCertSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, k, err
}

func issue(root *x509.Certificate, rootKey crypto.Signer, name string, now time.Time) (tls.Certificate, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	t := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(LeafLife),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, t, root, &k.PublicKey, rootKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, root.Raw}, PrivateKey: k}, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}
