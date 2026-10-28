package camnode

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// The port's TLS (brief design point 4, questions 1 and 2): TLS 1.3 only,
// key exchange pinned to the hybrid X25519MLKEM768 as on the edge link
// (D-149), P-256 keys on both ends, each end pinning the other's key rather
// than a chain, so the node needs no clock and no certificate authority.
// No session resumption: every connection proves its key afresh.

// Group is the port's only key exchange.
const Group = tls.X25519MLKEM768

var (
	ErrPeer = errors.New("camnode: peer certificate is not one self-signed P-256 certificate")
	ErrPin  = errors.New("camnode: peer key is not pinned for any role")
	ErrKey  = errors.New("camnode: key is not P-256")
)

// serverConfig is the node's configuration. The certificate is signed by a
// throwaway key, so the element signs TLS handshakes and nothing else; the
// core pins the device key, and the CertificateVerify proves the node holds
// it. admit is asked during the handshake, so a client no role admits is
// refused there.
func serverConfig(s signer, admit func([camwire.PointLen]byte) bool) (*tls.Config, error) {
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template(), template(), s.pub, throwaway)
	if err != nil {
		return nil, err
	}
	c := base()
	c.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: s}}
	c.ClientAuth = tls.RequireAnyClientCert
	c.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		pt, err := selfSignedP256(raw)
		if err != nil {
			return err
		}
		if !admit(pt) {
			return ErrPin
		}
		return nil
	}
	return c, nil
}

// ClientConfig is the core's and the enforcer's configuration, here so the
// node's tests and CAM-clerk share one definition. key is the client's own
// P-256 key, which signs its self-signed certificate; node is the node's
// device key, pinned.
func ClientConfig(key crypto.Signer, node [camwire.PointLen]byte) (*tls.Config, error) {
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template(), template(), pub, key)
	if err != nil {
		return nil, err
	}
	c := base()
	c.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
	// No chain to verify: the node's key is pinned below.
	c.InsecureSkipVerify = true
	c.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) != 1 {
			return ErrPeer
		}
		cert, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return ErrPeer
		}
		k, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return ErrPin
		}
		if pt, err := k.Bytes(); err != nil || [camwire.PointLen]byte(pt) != node {
			return ErrPin
		}
		return nil
	}
	return c, nil
}

// peerPoint is the P-256 key the peer proved on a completed handshake.
func peerPoint(cs tls.ConnectionState) ([camwire.PointLen]byte, bool) {
	if !cs.HandshakeComplete || cs.Version != tls.VersionTLS13 || cs.CurveID != Group || len(cs.PeerCertificates) != 1 {
		return [camwire.PointLen]byte{}, false
	}
	return point(cs.PeerCertificates[0])
}

func base() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{Group},
		SessionTicketsDisabled: true,
	}
}

// selfSignedP256 holds the client's certificate to its shape: exactly one,
// P-256, signed by its own key. It pins nothing.
func selfSignedP256(raw [][]byte) ([camwire.PointLen]byte, error) {
	var none [camwire.PointLen]byte
	if len(raw) != 1 {
		return none, ErrPeer
	}
	cert, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return none, ErrPeer
	}
	pt, ok := point(cert)
	if !ok || cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil {
		return none, ErrPeer
	}
	return pt, nil
}

func point(cert *x509.Certificate) ([camwire.PointLen]byte, bool) {
	var out [camwire.PointLen]byte
	k, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() {
		return out, false
	}
	b, err := k.Bytes()
	if err != nil || len(b) != camwire.PointLen {
		return out, false
	}
	copy(out[:], b)
	return out, true
}

// template is the fixed shape of both ends' certificates. Neither end
// checks validity; the dates only make the certificate well formed.
func template() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agentos camera node"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
	}
}
