package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/edgelink"
)

// fakeKernel is the kernel's link side as the link sees it: it holds the
// link key and answers for edge keys from what the test sets.
type fakeKernel struct {
	link ed25519.PrivateKey

	mu         sync.Mutex
	live       ed25519.PublicKey
	revoked    map[string]bool
	asked      int // edgekey calls
	candidates []hello
}

func newFakeKernel(t *testing.T) *fakeKernel {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKernel{link: priv, revoked: map[string]bool{}}
}

func (k *fakeKernel) LinkKey() (ed25519.PublicKey, error) {
	return k.link.Public().(ed25519.PublicKey), nil
}

func (k *fakeKernel) LinkSign(msg []byte) ([]byte, error) { return ed25519.Sign(k.link, msg), nil }

func (k *fakeKernel) EdgeKey(e ed25519.PublicKey) (Edge, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.asked++
	return Edge{Live: k.live != nil && k.live.Equal(e), Revoked: k.revoked[string(e)]}, nil
}

func (k *fakeKernel) EdgeCandidate(e ed25519.PublicKey, nonce, sig []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.candidates = append(k.candidates, hello{e, nonce, sig})
	return nil
}

func (k *fakeKernel) setLive(e ed25519.PublicKey) {
	k.mu.Lock()
	k.live = e
	k.mu.Unlock()
}

func (k *fakeKernel) counts() (asked, candidates int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.asked, len(k.candidates)
}

// edge is a test edge box: its key and the link client edgelink defines.
type edge struct {
	t      *testing.T
	signer crypto.Signer
}

func newEdge(t *testing.T) edge {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return edge{t, priv}
}

func (e edge) key() ed25519.PublicKey { return e.signer.Public().(ed25519.PublicKey) }

// dial completes a handshake with the core at addr, pinning pin.
func (e edge) dial(addr string, pin ed25519.PublicKey) *tls.Conn {
	e.t.Helper()
	cfg, err := edgelink.ClientConfig(e.signer, pin)
	if err != nil {
		e.t.Fatal(err)
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, cfg)
	if err != nil {
		e.t.Fatalf("dial: %v", err)
	}
	return c
}

// helloBody is the edge's hello for conn, signed over nonce (conn's own
// exporter value unless the test gives another).
func (e edge) helloBody(conn *tls.Conn, nonce []byte) []byte {
	e.t.Helper()
	if nonce == nil {
		var err error
		if nonce, err = edgelink.HelloNonce(conn.ConnectionState()); err != nil {
			e.t.Fatal(err)
		}
	}
	sig, err := edgelink.SignHello(e.signer, nonce)
	if err != nil {
		e.t.Fatal(err)
	}
	return sig
}

func frame(t *testing.T, s edgelink.Stream, f edgelink.Frame) []byte {
	t.Helper()
	b, err := edgelink.AppendFrame(nil, s, f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func helloFrame(t *testing.T, body []byte) []byte {
	return frame(t, edgelink.Hello, edgelink.Frame{Kind: edgelink.KindHello, Body: body})
}

// closedWithin reports whether the core closes conn within d.
func closedWithin(conn net.Conn, d time.Duration) bool {
	conn.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, conn)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return true
}

// smallOrderSigner is the identity point as an Ed25519 key, with the
// signature (R the identity, S zero) that verifies over any message.
type smallOrderSigner struct{}

var identityKey = ed25519.PublicKey(append([]byte{1}, make([]byte, 31)...))

func (smallOrderSigner) Public() crypto.PublicKey { return identityKey }
func (smallOrderSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return append([]byte{1}, make([]byte, 63)...), nil
}

// syncBuffer is a log the server writes from several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func eventually(t *testing.T, d time.Duration, ok func() bool) bool {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return true
		}
	}
	return ok()
}
