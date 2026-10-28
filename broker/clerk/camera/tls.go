package camera

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// The stream port's TLS, as the node serves it (CAM-node brief design
// point 4): TLS 1.3 only, the hybrid X25519MLKEM768 key exchange alone (as
// the edge link, D-149), no session resumption, a self-signed P-256
// certificate on each end, and each end pinning the other's key rather
// than a chain or a name.

// Group is the port's only key exchange.
const Group = tls.X25519MLKEM768

var (
	// errPin is the node's leaf key differing from the pin; the clerk turns
	// it into ErrSpoofed.
	errPin = errors.New("camera: node key does not match its pin")
	// errHandshake is every other dial or handshake failure, in fixed text
	// so nothing from the node or the key reaches a caller.
	errHandshake = errors.New("camera: dial or handshake failed")
)

// SPKIHash is a node key's pin: the SHA-256 of its SubjectPublicKeyInfo,
// as netguard.KeyHash computes it from a certificate.
func SPKIHash(point [camwire.PointLen]byte) ([32]byte, error) {
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point[:])
	if err != nil {
		return [32]byte{}, err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(der), nil
}

// ClientPoint is the core's client public key, which goes back to the
// enforcer for the node's next owner-signed bundle (brief question 4).
func ClientPoint(lend func(fn func(key []byte) error) error) ([camwire.PointLen]byte, error) {
	var out [camwire.PointLen]byte
	err := lend(func(k []byte) error {
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), k)
		if err != nil {
			return errHandshake
		}
		b, err := priv.PublicKey.Bytes()
		if err != nil || len(b) != camwire.PointLen {
			return errHandshake
		}
		copy(out[:], b)
		return nil
	})
	if err != nil {
		return [camwire.PointLen]byte{}, errHandshake
	}
	return out, nil
}

// dial opens the camera's stream: its pinned address only, through the
// device guard, then the TLS handshake with the client key lent for the
// handshake alone. A node key other than the pin is ErrSpoofed, found
// before any application byte is read.
func (c *Clerk) dial(ctx context.Context, cm Camera) (net.Conn, error) {
	if !homeAddr(cm.Addr) {
		return nil, ErrAddress
	}
	pin, err := SPKIHash(cm.Key)
	if err != nil {
		return nil, ErrCamera
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	raw, err := c.cfg.Guard.DialContext(netguard.WithPurpose(ctx, netguard.PurposeDevice), "tcp", cm.Addr.String())
	if err != nil {
		if errors.Is(err, netguard.ErrDenied) {
			return nil, netguard.ErrDenied
		}
		return nil, errHandshake
	}
	// The deadline bounds the handshake's writes too, which the context
	// does not once the handshake has failed and sends its alert.
	if err := raw.SetDeadline(time.Now().Add(c.cfg.Timeout)); err != nil {
		raw.Close()
		return nil, errHandshake
	}
	var tc *tls.Conn
	err = c.cfg.Lend(func(k []byte) error {
		priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), k)
		if err != nil {
			return errHandshake
		}
		cfg, err := clientConfig(priv, pin)
		if err != nil {
			return errHandshake
		}
		tc = tls.Client(raw, cfg)
		return tc.HandshakeContext(ctx)
	})
	if err != nil {
		raw.Close()
		if errors.Is(err, errPin) {
			return nil, ErrSpoofed
		}
		return nil, errHandshake
	}
	if err := raw.SetDeadline(time.Time{}); err != nil {
		tc.Close()
		return nil, errHandshake
	}
	return tc, nil
}

// clientConfig presents key's self-signed certificate and admits only a
// node whose single certificate carries the pinned key.
func clientConfig(key crypto.Signer, pin [32]byte) (*tls.Config, error) {
	der, err := x509.CreateCertificate(rand.Reader, template(), template(), key.Public(), key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{Group},
		SessionTicketsDisabled: true,
		Certificates:           []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		// No chain or name: the node's key is pinned below. The check runs
		// on the server's Certificate message, before its CertificateVerify
		// and before any application byte.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || netguard.KeyHash(cs.PeerCertificates[0]) != pin {
				return errPin
			}
			if len(cs.PeerCertificates) != 1 || cs.Version != tls.VersionTLS13 {
				return errHandshake
			}
			return nil
		},
	}, nil
}

// template is the client certificate's fixed shape. The node checks its
// self-signature and key only; the dates only make it well formed.
func template() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agentos camera client"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
	}
}
