package edgelink

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"time"
)

// The link's TLS (decision 5 of briefs/EDGE-link-core.md): TLS 1.3 only,
// key exchange pinned to the hybrid X25519MLKEM768 (D-149), Ed25519
// certificates on both ends, no session resumption (every connection runs
// a full handshake, so each proves its key afresh and the core asks the
// kernel about that key on every connection).

// Group is the link's only key exchange.
const Group = tls.X25519MLKEM768

var (
	ErrPeer = errors.New("edgelink: peer certificate is not one self-signed Ed25519 certificate")
	ErrPin  = errors.New("edgelink: peer key is not the pinned key")
	ErrKey  = errors.New("edgelink: key is not Ed25519")
	// ErrNotCertificateVerify is the guarded signer's refusal of anything
	// but a TLS 1.3 CertificateVerify input.
	ErrNotCertificateVerify = errors.New("edgelink: signer refuses input that is not a TLS 1.3 CertificateVerify")
	ErrState                = errors.New("edgelink: connection is not a completed TLS 1.3 hybrid handshake")
)

const (
	serverContext = "TLS 1.3, server CertificateVerify"
	clientContext = "TLS 1.3, client CertificateVerify"
)

// ServerConfig is the core's configuration. signer is the core's link key
// (or, before enrolment, an ephemeral key); TLS calls it only through a
// guard that passes a server CertificateVerify input and nothing else, the
// shape the kernel's linksign checks (decision 4). The certificate's own
// signature is made by a throwaway key, not by signer, so signer never
// signs a certificate: the edge pins the core's key, not the certificate,
// and the CertificateVerify is what proves the core holds it.
//
// The client must present one self-signed Ed25519 certificate; any key is
// accepted, since which key is live is the kernel's answer, asked after
// the handshake (PeerKey).
func ServerConfig(signer crypto.Signer) (*tls.Config, error) {
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrKey
	}
	_, throwaway, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template(), template(), pub, throwaway)
	if err != nil {
		return nil, err
	}
	c := base()
	c.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: guard{signer, serverContext}}}
	c.ClientAuth = tls.RequireAnyClientCert
	c.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		_, err := selfSignedEd25519(raw)
		return err
	}
	return c, nil
}

// ClientConfig is the edge's configuration, here so the core's tests and
// the edge-side row share one definition. signer is the edge's own key,
// which signs its self-signed certificate; pin is the core's link key.
func ClientConfig(signer crypto.Signer, pin ed25519.PublicKey) (*tls.Config, error) {
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok || len(pin) != ed25519.PublicKeySize {
		return nil, ErrKey
	}
	der, err := x509.CreateCertificate(rand.Reader, template(), template(), pub, signer)
	if err != nil {
		return nil, err
	}
	c := base()
	c.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: guard{signer, clientContext}}}
	// No chain to verify: the core's key is pinned below.
	c.InsecureSkipVerify = true
	pin = bytes.Clone(pin)
	c.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) != 1 {
			return ErrPeer
		}
		cert, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return ErrPeer
		}
		if k, ok := cert.PublicKey.(ed25519.PublicKey); !ok || !bytes.Equal(k, pin) {
			return ErrPin
		}
		return nil
	}
	return c, nil
}

// PeerKey is the Ed25519 key the peer proved on a completed handshake.
func PeerKey(cs tls.ConnectionState) (ed25519.PublicKey, error) {
	if !cs.HandshakeComplete || cs.Version != tls.VersionTLS13 || cs.CurveID != Group || len(cs.PeerCertificates) != 1 {
		return nil, ErrState
	}
	k, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, ErrState
	}
	return bytes.Clone(k), nil
}

func base() *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{Group},
		SessionTicketsDisabled: true,
	}
}

// selfSignedEd25519 holds the client's certificate to its shape: exactly
// one, Ed25519, signed by its own key. It pins nothing.
func selfSignedEd25519(raw [][]byte) (ed25519.PublicKey, error) {
	if len(raw) != 1 {
		return nil, ErrPeer
	}
	cert, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return nil, ErrPeer
	}
	k, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || cert.SignatureAlgorithm != x509.PureEd25519 {
		return nil, ErrPeer
	}
	if cert.CheckSignature(x509.PureEd25519, cert.RawTBSCertificate, cert.Signature) != nil {
		return nil, ErrPeer
	}
	return k, nil
}

// template is the fixed shape of both ends' certificates. Validity is not
// checked by either end; the dates only make the certificate well formed.
func template() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agentos edge link"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
	}
}

// guard is the signer TLS sees: it passes a TLS 1.3 CertificateVerify
// input for its context and refuses everything else, so a TLS stack that
// asked for any other signature would fail here as linksign fails it.
type guard struct {
	s       crypto.Signer
	context string
}

func (g guard) Public() crypto.PublicKey { return g.s.Public() }

func (g guard) Sign(r io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != 0 || !certificateVerifyInput(msg, g.context) {
		return nil, ErrNotCertificateVerify
	}
	return g.s.Sign(r, msg, opts)
}

// certificateVerifyInput reports whether msg is RFC 8446 §4.4.3's signed
// content for context: 64 spaces, the context string, a zero byte and a
// 32- or 48-byte transcript hash.
func certificateVerifyInput(msg []byte, context string) bool {
	prefix := len(context) + 65
	if n := len(msg) - prefix; n != 32 && n != 48 {
		return false
	}
	return bytes.Equal(msg[:64], bytes.Repeat([]byte{' '}, 64)) &&
		string(msg[64:64+len(context)]) == context && msg[prefix-1] == 0
}
