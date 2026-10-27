// Package pageca is the core's page authority (OWN-page-https, #3153; SPEC
// CH-9, HW-1, §19 risk 30): a self-signed ECDSA P-256 root whose critical
// name constraint admits exactly one DNS name, the owner page's, and no
// subdomain or IP address, so a phone that installs it trusts it for that
// page and nothing else. The kernel holds it from the sealed store and its
// key never leaves the kernel: the web-facing page (agentos-localui) makes
// its own serving key and asks agentosd to certify it (localapi.OpCertify),
// which forwards to the kernel's certify (MIG-4-recovery-f2).
//
// It imports the standard library only, since clerk links crypto/tls and
// net/http, which agentosd's control path may not depend on (ARC-2).
package pageca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"time"
)

// DefaultName is the owner page's name: a leaf under ICANN's private-use
// TLD, never served on a subdomain (brief design 1).
const DefaultName = "agentos.internal"

// AuthorityYears is the authority's lifetime from its NotBefore.
const AuthorityYears = 30

// MaxLeaf caps a serving certificate's lifetime (825 days, the platforms'
// limit for TLS server certificates).
const MaxLeaf = 825 * 24 * time.Hour

// Authority is the page authority: its certificate and its key.
type Authority struct {
	name  string
	built time.Time
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
}

// ErrName is a name that is not one lowercase DNS name with a dot.
var ErrName = errors.New("pageca: not a page name")

// ValidName reports whether name can be the page's: lowercase letters,
// digits and hyphens in dot-separated labels, at least two labels, no IP
// address, no trailing dot.
func ValidName(name string) bool {
	if len(name) == 0 || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// New makes an authority for name. Its NotBefore is one day before built,
// the image's build time, never the clock, so a wrong first-boot clock
// cannot stamp a root phones refuse (brief design 3).
func New(name string, built time.Time, r io.Reader) (*Authority, error) {
	if !ValidName(name) {
		return nil, ErrName
	}
	if built.IsZero() {
		return nil, errors.New("pageca: no build time")
	}
	if r == nil {
		r = rand.Reader
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return nil, err
	}
	serial, err := serialNumber(r)
	if err != nil {
		return nil, err
	}
	nb := built.UTC().Truncate(time.Second).Add(-24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: "agentOS page authority " + name},
		NotBefore:                   nb,
		NotAfter:                    nb.AddDate(AuthorityYears, 0, 0),
		KeyUsage:                    x509.KeyUsageCertSign,
		ExtKeyUsage:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{name},
		ExcludedDNSDomains:          []string{"." + name},
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
	}
	der, err := x509.CreateCertificate(r, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{name: name, built: nb.Add(24 * time.Hour), cert: cert, key: key}, nil
}

// fromParts rebuilds an authority from its certificate and key, checking
// that they are one pair, made by New for name.
func fromParts(name string, certDER []byte, key *ecdsa.PrivateKey) (*Authority, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	switch {
	case !ok || !pub.Equal(&key.PublicKey) || key.Curve != elliptic.P256():
		return nil, errors.New("pageca: key and certificate differ")
	case !cert.IsCA || !cert.MaxPathLenZero || !cert.PermittedDNSDomainsCritical,
		len(cert.PermittedDNSDomains) != 1 || cert.PermittedDNSDomains[0] != name:
		return nil, errors.New("pageca: not this page's authority")
	}
	return &Authority{name: name, built: cert.NotBefore.Add(24 * time.Hour), cert: cert, key: key}, nil
}

// Certificate is the authority's certificate, DER.
func (a *Authority) Certificate() []byte { return append([]byte(nil), a.cert.Raw...) }

// Name is the page name the authority admits.
func (a *Authority) Name() string { return a.name }

// Fingerprint is SHA-256 of the certificate's DER, uppercase hex in groups
// of four, for the Owner Card.
func (a *Authority) Fingerprint() string { return Fingerprint(a.cert.Raw) }

// Fingerprint renders SHA-256 of der as the card prints it.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(h); i += 4 {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(h[i : i+4])
	}
	return b.String()
}

// ErrKey is a serving key Issue does not sign: not ECDSA P-256 in PKIX DER.
var ErrKey = errors.New("pageca: the serving key is not ECDSA P-256")

// ErrExpired is an authority past its NotAfter at now.
var ErrExpired = errors.New("pageca: the authority has expired")

// Issue certifies pub (PKIX DER, ECDSA P-256 only) for the page name only,
// for server authentication only. NotBefore is the later of the build time
// and a day before now; NotAfter is the earlier of 825 days after that and
// the authority's own NotAfter. It returns the leaf, DER.
func (a *Authority) Issue(pubDER []byte, now time.Time, r io.Reader) ([]byte, error) {
	pk, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, ErrKey
	}
	pub, ok := pk.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrKey
	}
	if r == nil {
		r = rand.Reader
	}
	nb := now.UTC().Truncate(time.Second).Add(-24 * time.Hour)
	if nb.Before(a.built) {
		nb = a.built
	}
	na := nb.Add(MaxLeaf)
	if na.After(a.cert.NotAfter) {
		na = a.cert.NotAfter
	}
	if !nb.Before(na) {
		return nil, ErrExpired
	}
	serial, err := serialNumber(r)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: a.name},
		DNSNames:              []string{a.name},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	return x509.CreateCertificate(r, tmpl, a.cert, pub, a.key)
}

func serialNumber(r io.Reader) (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	b[0] &= 0x7f
	b[0] |= 0x40 // never zero, never negative
	return new(big.Int).SetBytes(b), nil
}
