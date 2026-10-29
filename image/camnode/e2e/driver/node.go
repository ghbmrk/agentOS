package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/camnode"
	"github.com/ghbmrk/agentos/broker/camwire"
)

// rp is the synthetic enforcer page's relying-party ID, as camwiretest's.
const rp = "enforcer.home.arpa"

// passkey is a synthetic owner passkey: a P-256 key generated per run that answers a WebAuthn
// get() the way a platform passkey does (camwiretest.Passkey, without testing.TB). It holds no
// real credential.
type passkey struct{ priv *ecdsa.PrivateKey }

func newKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func pointOf(k *ecdsa.PublicKey) [camwire.PointLen]byte {
	b, err := k.Bytes()
	if err != nil {
		panic(err)
	}
	return [camwire.PointLen]byte(b)
}

func (p passkey) owner() camwire.Owner {
	return camwire.Owner{RPID: rp, Point: pointOf(&p.priv.PublicKey)}
}

// assert is the passkey's honest assertion over msg: user present and verified, challenge
// camwire.Challenge(msg), origin https://rp.
func (p passkey) assert(msg []byte) camwire.Assertion {
	h := sha256.Sum256([]byte(rp))
	ad := append(h[:], 0x01|0x04, 0, 0, 0, 0)
	ch := camwire.Challenge(msg)
	cd, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   base64.RawURLEncoding.EncodeToString(ch[:]),
		"origin":      "https://" + rp,
		"crossOrigin": false,
	})
	if err != nil {
		panic(err)
	}
	cdh := sha256.Sum256(cd)
	sh := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.priv, sh[:])
	if err != nil {
		panic(err)
	}
	return camwire.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig}
}

func (p passkey) signBundle(b camwire.Bundle) []byte {
	enc, err := b.Encode()
	if err != nil {
		panic(err)
	}
	out, err := camwire.SignedBundle{Bundle: enc, Assertion: p.assert(enc)}.Encode()
	if err != nil {
		panic(err)
	}
	return out
}

// keys is one run's synthetic parties: the owner's passkey, the core's and the enforcer's
// client keys, and the release signer whose public half the image under test carries.
type keys struct {
	owner    passkey
	core     *ecdsa.PrivateKey
	enforcer *ecdsa.PrivateKey
	release  ed25519.PrivateKey
}

func loadRelease(base string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(base + ".key")
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("release key is not a base64 Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// keygen writes a throwaway release signer for a test image: BASE.key (the seed, 0600) and
// BASE.pub (the public key, as agentos-camnode -release reads it).
func keygen(base string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(base+".key", []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(base+".pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644)
}

// signManifest is a manifest the release signer signed and the owner approved.
func (k keys) signManifest(m camwire.Manifest, approver passkey) []byte {
	enc, err := m.Encode()
	if err != nil {
		panic(err)
	}
	s := camwire.SignedManifest{Manifest: enc, Assertion: approver.assert(enc)}
	copy(s.Release[:], ed25519.Sign(k.release, enc))
	out, err := s.Encode()
	if err != nil {
		panic(err)
	}
	return out
}

// conn is one TLS connection to the node's one port.
type conn struct {
	c *tls.Conn
}

// dial connects with key, pinning the node's key when node is set, and returns the key the node
// presented.
func dial(addr string, key *ecdsa.PrivateKey, node *[camwire.PointLen]byte) (*conn, [camwire.PointLen]byte, error) {
	var seen [camwire.PointLen]byte
	var cfg *tls.Config
	var err error
	if node != nil {
		cfg, err = camnode.ClientConfig(key, *node)
		if err != nil {
			return nil, seen, err
		}
	} else {
		// Learning the node's key on first contact, as the enforcer's page shows it for the
		// owner to compare with the case (brief question 5).
		cfg, err = camnode.ClientConfig(key, seen)
		if err != nil {
			return nil, seen, err
		}
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) != 1 {
				return camnode.ErrPeer
			}
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			k, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return camnode.ErrPeer
			}
			seen = pointOf(k)
			return nil
		}
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, seen, err
	}
	c := tls.Client(raw, cfg)
	c.SetDeadline(time.Now().Add(30 * time.Second))
	if err := c.Handshake(); err != nil {
		raw.Close()
		return nil, seen, err
	}
	if node != nil {
		seen = *node
	}
	return &conn{c: c}, seen, nil
}

func (c *conn) close() { c.c.Close() }

// refused reports whether the node refuses key. In TLS 1.3 the client's handshake completes
// before the server has checked the client's certificate, so a refusal shows either as a failed
// handshake or as the node's alert, or a closed connection, on the first read; a read that
// times out is a connection the node kept, an admission.
func refused(addr string, key *ecdsa.PrivateKey) bool {
	c, _, err := dial(addr, key, nil)
	if err != nil {
		return true
	}
	defer c.close()
	return c.closed(10 * time.Second)
}

// readFrame reads one frame the node sends (the core's direction or the enforcer's).
func (c *conn) readFrame(d camwire.Direction, timeout time.Duration) (camwire.Frame, error) {
	c.c.SetReadDeadline(time.Now().Add(timeout))
	return camwire.ReadFrame(c.c, d, camwire.Shape{})
}

func (c *conn) send(t camwire.Type, p []byte) error {
	c.c.SetWriteDeadline(time.Now().Add(60 * time.Second))
	return camwire.WriteFrame(c.c, camwire.FromEnforcer, camwire.Shape{}, camwire.Frame{Type: t, Payload: p})
}

// status reads the enforcer channel's status record.
func (c *conn) status(timeout time.Duration) (camwire.Status, error) {
	f, err := c.readFrame(camwire.ToEnforcer, timeout)
	if err != nil {
		return camwire.Status{}, err
	}
	if f.Type != camwire.TypeStatus {
		return camwire.Status{}, fmt.Errorf("frame type %d, not status", f.Type)
	}
	return camwire.ParseStatus(f.Payload)
}

// closed reports whether the node ends the connection within timeout without sending anything.
func (c *conn) closed(timeout time.Duration) bool {
	c.c.SetReadDeadline(time.Now().Add(timeout))
	var b [1]byte
	_, err := c.c.Read(b[:])
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}
