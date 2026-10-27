package edgelink

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// REQ: HW-15, HW-17

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// handshake runs one connection over a pipe and returns both ends' states
// and errors. Both ends are closed when either fails.
func handshake(t *testing.T, server, client *tls.Config) (tls.ConnectionState, tls.ConnectionState, error, error) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	s, c := tls.Server(a, server), tls.Client(b, client)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	var serr, cerr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		if serr = s.HandshakeContext(ctx); serr != nil {
			a.Close()
		}
	}()
	go func() {
		defer wg.Done()
		if cerr = c.HandshakeContext(ctx); cerr != nil {
			b.Close()
			return
		}
		// TLS 1.3 completes the client's side before the server has judged
		// the client's certificate: read once so a refusal reaches it.
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := c.Read(make([]byte, 1)); err != nil && !isTimeout(err) {
			cerr = err
		}
	}()
	wg.Wait()
	return s.ConnectionState(), c.ConnectionState(), serr, cerr
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

// TestHandshakeShape: any self-signed Ed25519 client completes and its key
// is returned; no client certificate, another key type, a certificate not
// signed by its own key, TLS 1.2 or a classical-only key exchange fails.
// Revert mutants: VerifyPeerCertificate removed (the ECDSA, cross-signed
// and two-certificate cases pass), CurvePreferences dropped (the
// classical-only case passes). Two defences are doubled, so their one-line
// reverts survive by design: RequireAnyClientCert and the certificate check
// both refuse no certificate, and MinVersion and the hybrid group both
// refuse TLS 1.2 (1.2 cannot negotiate X25519MLKEM768).
func TestHandshakeShape(t *testing.T) {
	core, edge := newKey(t), newKey(t)
	scfg, err := ServerConfig(core)
	if err != nil {
		t.Fatal(err)
	}
	ccfg, err := ClientConfig(edge, core.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	ss, cs, serr, cerr := handshake(t, scfg, ccfg)
	if serr != nil || cerr != nil {
		t.Fatalf("good handshake: server %v, client %v", serr, cerr)
	}
	got, err := PeerKey(ss)
	if err != nil || !bytes.Equal(got, edge.Public().(ed25519.PublicKey)) {
		t.Fatalf("server's PeerKey = %x, %v; want the edge's key", got, err)
	}
	if ss.CurveID != tls.X25519MLKEM768 || ss.Version != tls.VersionTLS13 || ss.DidResume {
		t.Fatalf("negotiated %v / %x / resumed %v", ss.CurveID, ss.Version, ss.DidResume)
	}
	if got, err := PeerKey(cs); err != nil || !bytes.Equal(got, core.Public().(ed25519.PublicKey)) {
		t.Fatalf("client's PeerKey = %x, %v; want the core's key", got, err)
	}

	// No resumption: a client that keeps a session cache still runs a full
	// handshake each time, so each connection proves its key afresh
	// (decision 5, ASSUMPTIONS EDGE-link-c1-6). Revert mutant: deleting
	// SessionTicketsDisabled (connections 2 and 3 resume).
	caching, _ := ClientConfig(edge, core.Public().(ed25519.PublicKey))
	caching.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	for i := 0; i < 3; i++ {
		ss, cs, serr, cerr := handshake(t, scfg, caching)
		if serr != nil || cerr != nil {
			t.Fatalf("caching client %d: server %v, client %v", i, serr, cerr)
		}
		if ss.DidResume || cs.DidResume {
			t.Fatalf("caching client %d resumed", i)
		}
	}

	// Any Ed25519 client key is accepted at the handshake: liveness is the kernel's answer.
	other, _ := ClientConfig(newKey(t), core.Public().(ed25519.PublicKey))
	if _, _, serr, cerr := handshake(t, scfg, other); serr != nil || cerr != nil {
		t.Fatalf("another Ed25519 edge: server %v, client %v", serr, cerr)
	}

	edgeCert := ccfg.Certificates[0]
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.CreateCertificate(rand.Reader, template(), template(), &ecKey.PublicKey, ecKey)
	edPub := edge.Public().(ed25519.PublicKey)
	crossDER, _ := x509.CreateCertificate(rand.Reader, template(), template(), edPub, newKey(t))
	raw := func(mut func(*tls.Config)) *tls.Config {
		c := &tls.Config{
			MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{edgeCert},
		}
		mut(c)
		return c
	}
	bad := map[string]*tls.Config{
		"no client certificate": raw(func(c *tls.Config) { c.Certificates = nil }),
		"ECDSA client": raw(func(c *tls.Config) {
			c.Certificates = []tls.Certificate{{Certificate: [][]byte{ecDER}, PrivateKey: ecKey}}
		}),
		"not self-signed": raw(func(c *tls.Config) {
			c.Certificates = []tls.Certificate{{Certificate: [][]byte{crossDER}, PrivateKey: edge}}
		}),
		"two certificates": raw(func(c *tls.Config) {
			c.Certificates = []tls.Certificate{{Certificate: [][]byte{edgeCert.Certificate[0], edgeCert.Certificate[0]}, PrivateKey: edge}}
		}),
		"TLS 1.2": raw(func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 }),
		"classical key exchange": raw(func(c *tls.Config) {
			c.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
		}),
	}
	for name, c := range bad {
		if _, _, serr, _ := handshake(t, scfg, c); serr == nil {
			t.Errorf("%s: the core completed the handshake", name)
		}
	}

	// The edge refuses a core that is not its pinned key.
	wrong, _ := ClientConfig(edge, newKey(t).Public().(ed25519.PublicKey))
	if _, _, _, cerr := handshake(t, scfg, wrong); cerr == nil {
		t.Error("the edge accepted a core key it did not pin")
	}

	if _, err := ServerConfig(ecKey); err != ErrKey {
		t.Errorf("ServerConfig with an ECDSA key: %v", err)
	}
	if _, err := ClientConfig(edge, nil); err != ErrKey {
		t.Errorf("ClientConfig without a pin: %v", err)
	}
	if _, err := PeerKey(tls.ConnectionState{}); err != ErrState {
		t.Errorf("PeerKey of an incomplete state: %v", err)
	}
}

// recorder is a signer that records every input it is asked to sign.
type recorder struct {
	crypto.Signer
	mu   sync.Mutex
	msgs [][]byte
}

func (r *recorder) Sign(rnd io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	r.mu.Lock()
	r.msgs = append(r.msgs, bytes.Clone(msg))
	r.mu.Unlock()
	return r.Signer.Sign(rnd, msg, opts)
}

// TestSignerSeesOnlyCertificateVerify: building the server's configuration
// and running handshakes asks the core's signer for nothing but TLS 1.3
// server CertificateVerify inputs, the one shape linksign will sign; and
// the guard refuses anything else before it reaches the signer. Revert
// mutants: ServerConfig self-signing its certificate with signer (a
// certificate TBS reaches it), or guard.Sign passing every input through.
func TestSignerSeesOnlyCertificateVerify(t *testing.T) {
	rec := &recorder{Signer: newKey(t)}
	scfg, err := ServerConfig(rec)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.msgs) != 0 {
		t.Fatalf("ServerConfig asked the signer for %d signatures", len(rec.msgs))
	}
	for i := 0; i < 3; i++ {
		ccfg, _ := ClientConfig(newKey(t), rec.Public().(ed25519.PublicKey))
		if _, _, serr, cerr := handshake(t, scfg, ccfg); serr != nil || cerr != nil {
			t.Fatalf("handshake: %v, %v", serr, cerr)
		}
	}
	if len(rec.msgs) != 3 {
		t.Fatalf("signer asked %d times over 3 handshakes, want 3", len(rec.msgs))
	}
	space := bytes.Repeat([]byte{' '}, 64)
	for _, m := range rec.msgs {
		want := append(append(append([]byte{}, space...), "TLS 1.3, server CertificateVerify"...), 0)
		if !bytes.HasPrefix(m, want) || (len(m)-len(want) != 32 && len(m)-len(want) != 48) {
			t.Fatalf("signer saw %q, not a server CertificateVerify input", m)
		}
	}

	rec.msgs = nil
	g := scfg.Certificates[0].PrivateKey.(crypto.Signer)
	hash := bytes.Repeat([]byte{9}, 32)
	refused := map[string][]byte{
		"empty":           {},
		"certificate TBS": []byte("\x30\x82\x01\x00 a certificate"),
		"client context":  append(append(append(append([]byte{}, space...), "TLS 1.3, client CertificateVerify"...), 0), hash...),
		"no zero byte":    append(append(append(append([]byte{}, space...), "TLS 1.3, server CertificateVerify"...), 1), hash...),
		"31-byte hash":    append(append(append(append([]byte{}, space...), "TLS 1.3, server CertificateVerify"...), 0), hash[:31]...),
		"64-byte hash":    append(append(append(append([]byte{}, space...), "TLS 1.3, server CertificateVerify"...), 0), bytes.Repeat(hash, 2)...),
		"63 spaces":       append(append(append(append([]byte{}, space[:63]...), "xTLS 1.3, server CertificateVerify"...), 0), hash...),
		"a hello":         helloMessage(make([]byte, NonceLen)),
	}
	for name, m := range refused {
		if _, err := g.Sign(rand.Reader, m, crypto.Hash(0)); err != ErrNotCertificateVerify {
			t.Errorf("%s: guard returned %v", name, err)
		}
	}
	good := append(append(append(append([]byte{}, space...), "TLS 1.3, server CertificateVerify"...), 0), hash...)
	if _, err := g.Sign(rand.Reader, good, crypto.SHA256); err != ErrNotCertificateVerify {
		t.Errorf("a prehashed request passed the guard: %v", err)
	}
	if _, err := g.Sign(rand.Reader, good, crypto.Hash(0)); err != nil {
		t.Errorf("a CertificateVerify input was refused: %v", err)
	}
	if len(rec.msgs) != 1 {
		t.Fatalf("refused inputs reached the signer: %d calls", len(rec.msgs))
	}
}
