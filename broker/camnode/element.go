// Package camnode is the camera node's stream server (CAM-node part b,
// #3513; SPEC DEV-2, DEV-3, NET-2 Cameras, NET-4, A16): one TLS 1.3 port
// that gives the pinned core key the stream only and the pinned enforcer key
// the settings channel only, applies owner-signed settings bundles against
// the secure element's counters, and takes its first bundle only while the
// board's button was held at power-on.
//
// It makes no outbound connection (TestNoOutboundDial): the binary hands it
// a listener, and everything else reaches it through Element, Store and
// Source.
package camnode

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"io"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// Element is the secure element as the node uses it. The device key is
// generated inside it and never leaves it: there is no method that returns
// private key material (TestDeviceKeyNeverExported), only Public and Sign.
// The counters are the element's monotonic counters, which no method lowers.
type Element interface {
	// Public is the device key's public point.
	Public() ([camwire.PointLen]byte, error)
	// Sign is an ECDSA P-256 signature, ASN.1 DER, over a SHA-256 digest.
	Sign(digest []byte) ([]byte, error)
	// Settings is the settings counter and the SHA-256 of the signed bundle
	// last committed (zero: none since the last ClearBundle).
	Settings() (counter uint64, bundle [32]byte, err error)
	// CommitBundle records bundle, then raises the settings counter to
	// counter. A crash between the two leaves the record raised and the
	// counter below it, which New completes.
	CommitBundle(counter uint64, bundle [32]byte) error
	// ClearBundle zeroes the bundle record. The counter is kept.
	ClearBundle() error
	// Image is the image counter: the counter of the newest image this
	// node has marked good.
	Image() (uint64, error)
	// RaiseImage raises the image counter to counter, which must be above
	// it.
	RaiseImage(counter uint64) error
}

// ErrElement is the element answering with something other than what was
// asked: a malformed point or a failed command.
var ErrElement = errors.New("camnode: secure element answered malformed or failed")

// signer is the device key as crypto/tls sees it. It holds the element,
// not a key.
type signer struct {
	e   Element
	pub *ecdsa.PublicKey
}

func newSigner(e Element) (signer, [camwire.PointLen]byte, error) {
	pt, err := e.Public()
	if err != nil {
		return signer{}, pt, ErrElement
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt[:])
	if err != nil {
		return signer{}, pt, ErrElement
	}
	return signer{e, pub}, pt, nil
}

func (s signer) Public() crypto.PublicKey { return s.pub }

// Sign signs a SHA-256 digest only: TLS 1.3 with ECDSA P-256 asks for no
// other. It releases only a signature that verifies under the device key,
// so a faulted element signature (a fault attack's lever on ECDSA) never
// leaves the node (ASSUMPTIONS CAM-b2-1).
func (s signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, ErrElement
	}
	sig, err := s.e.Sign(digest)
	if err != nil || !ecdsa.VerifyASN1(s.pub, digest, sig) {
		return nil, ErrElement
	}
	return sig, nil
}
