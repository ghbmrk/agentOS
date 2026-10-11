package netguard

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
)

// ErrPinMismatch is returned by the handshake when a pinned name presents a
// key other than its pin. It wraps ErrDenied.
var ErrPinMismatch = &pinError{}

type pinError struct{}

func (*pinError) Error() string {
	return "netguard: destination refused: TLS key does not match its pin"
}
func (*pinError) Is(target error) bool { return target == ErrDenied }

// KeyHash is the pin of a certificate: the SHA-256 of its
// SubjectPublicKeyInfo.
func KeyHash(c *x509.Certificate) [32]byte { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

// TLSConfig returns a client config whose verification the policy owns. A
// pinned name is trusted by its key pin alone (a home device's certificate
// is usually self-signed), and fails the handshake, before any request
// byte, on any other key. Every other name gets the ordinary chain and
// name verification against base.RootCAs (the system roots when nil).
// base may be nil.
func (p *Policy) TLSConfig(base *tls.Config) *tls.Config {
	var c *tls.Config
	if base != nil {
		c = base.Clone()
	} else {
		c = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	c.InsecureSkipVerify = true // VerifyConnection below does the verifying
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("netguard: no certificate")
		}
		name := strings.ToLower(strings.TrimSuffix(cs.ServerName, "."))
		leaf := cs.PeerCertificates[0]
		p.mu.RLock()
		pins := p.pins
		p.mu.RUnlock()
		pinned := false
		for _, pin := range pins {
			if pin.Name != "" && pin.Name == name {
				pinned = true
				if KeyHash(leaf) == pin.Key {
					return nil
				}
			}
		}
		if pinned {
			return ErrPinMismatch
		}
		// An address-only pin has no name to match here; it is checked by
		// key against every pin of that address.
		if cs.ServerName == "" {
			for _, pin := range pins {
				if pin.Name == "" && KeyHash(leaf) == pin.Key {
					return nil
				}
			}
			return errors.New("netguard: no server name to verify")
		}
		inter := x509.NewCertPool()
		for _, ic := range cs.PeerCertificates[1:] {
			inter.AddCert(ic)
		}
		_, err := leaf.Verify(x509.VerifyOptions{DNSName: cs.ServerName, Roots: c.RootCAs, Intermediates: inter})
		return err
	}
	return c
}
