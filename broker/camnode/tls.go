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

// The node's TLS (brief design point 4, questions 1 and 2): TLS 1.3 only,
// ECDSA P-256 with SHA-256, key exchange pinned to the hybrid
// X25519MLKEM768 as the edge link is (D-149), no session resumption. The
// server signs only through the element; its certificate is signed by a
// throwaway key, since the core pins the node's key and not a certificate,
// so the element never signs anything but a handshake. Every client must
// present one certificate whose ECDSA P-256 key the bundle pins to a role;
// any other client fails the handshake.

// Group is the node's only key exchange.
const Group = tls.X25519MLKEM768

// Role is what a client key may do on the node's one port.
type Role uint8

const (
	// None is refused at the handshake.
	None Role = iota
	// Core gets the stream and nothing else.
	Core
	// Enforcer gets the settings channel and nothing else.
	Enforcer
	// Provisioner is any key while the first-bundle window is open: it
	// may send one bundle, which must name that key as the enforcer's.
	Provisioner
)

// ErrClient is a client certificate that is not one ECDSA P-256
// certificate, or whose key has no role.
var ErrClient = errors.New("camnode: client key is not pinned to a role")

// serverConfig is the node's TLS configuration. role is asked during the
// handshake for each client's key.
func serverConfig(signer crypto.Signer, role func([camwire.PointLen]byte) Role) (*tls.Config, error) {
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrClient
	}
	throwaway, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template(), template(), pub, throwaway)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{Group},
		SessionTicketsDisabled: true,
		Certificates: []tls.Certificate{{
			Certificate:                  [][]byte{der},
			PrivateKey:                   signer,
			SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		}},
		ClientAuth: tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			k, err := certKey(raw)
			if err != nil {
				return err
			}
			if role(k) == None {
				return ErrClient
			}
			return nil
		},
	}, nil
}

// certKey is the one ECDSA P-256 key a peer's certificate carries.
// The certificate's signature is not checked: the client proves the key
// in its CertificateVerify, and the pin is on the key.
func certKey(raw [][]byte) ([camwire.PointLen]byte, error) {
	var out [camwire.PointLen]byte
	if len(raw) != 1 {
		return out, ErrClient
	}
	cert, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return out, ErrClient
	}
	k, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || k.Curve != elliptic.P256() {
		return out, ErrClient
	}
	b, err := k.Bytes()
	if err != nil || len(b) != camwire.PointLen {
		return out, ErrClient
	}
	copy(out[:], b)
	return out, nil
}

// peerKey is the client key of a completed handshake.
func peerKey(cs tls.ConnectionState) ([camwire.PointLen]byte, error) {
	if !cs.HandshakeComplete || cs.Version != tls.VersionTLS13 || cs.CurveID != Group || len(cs.PeerCertificates) != 1 {
		return [camwire.PointLen]byte{}, ErrClient
	}
	return certKey([][]byte{cs.PeerCertificates[0].Raw})
}

// template is the certificates' fixed shape. Nothing checks validity: the
// node has no clock, and the dates only make the certificate well formed.
func template() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agentos camera node"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
	}
}

// ClientConfig is a client's configuration: the core's camera clerk or
// the enforcer, here so the node's tests and CAM-clerk share one
// definition. key is the client's own key; node is the node's pinned
// device key point.
func ClientConfig(key crypto.Signer, node [camwire.PointLen]byte) (*tls.Config, error) {
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrClient
	}
	der, err := x509.CreateCertificate(rand.Reader, template(), template(), pub, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{Group},
		SessionTicketsDisabled: true,
		Certificates:           []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		// No chain: the node's key is pinned below.
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			k, err := certKey(raw)
			if err != nil || k != node {
				return ErrClient
			}
			return nil
		},
	}, nil
}
