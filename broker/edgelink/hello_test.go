package edgelink

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"testing"
)

// REQ: HW-15, HW-17

// TestHelloBindsItsConnection: a hello verifies only against its own
// connection's exporter value, which both ends compute alike; one from
// another connection, under another domain, by another key, or not exactly
// 64 bytes refuses. This pins the hello for the edge-side row. Revert
// mutants: helloMessage dropping HelloDomain (the domain case passes) or
// the nonce (the other-connection case passes).
func TestHelloBindsItsConnection(t *testing.T) {
	core, edge := newKey(t), newKey(t)
	scfg, _ := ServerConfig(core)
	ccfg, _ := ClientConfig(edge, core.Public().(ed25519.PublicKey))
	s1, c1, serr, cerr := handshake(t, scfg, ccfg)
	if serr != nil || cerr != nil {
		t.Fatal(serr, cerr)
	}
	s2, _, serr, cerr := handshake(t, scfg, ccfg)
	if serr != nil || cerr != nil {
		t.Fatal(serr, cerr)
	}
	n1, err := HelloNonce(s1)
	if err != nil {
		t.Fatal(err)
	}
	if cn, _ := HelloNonce(c1); !bytes.Equal(cn, n1) {
		t.Fatal("the two ends of one connection disagree on the nonce")
	}
	n2, _ := HelloNonce(s2)
	if bytes.Equal(n1, n2) {
		t.Fatal("two connections share a nonce")
	}

	key := edge.Public().(ed25519.PublicKey)
	hello, err := SignHello(edge, n1)
	if err != nil || len(hello) != HelloLen {
		t.Fatalf("SignHello: %d bytes, %v", len(hello), err)
	}
	if err := VerifyHello(key, n1, hello); err != nil {
		t.Fatalf("own connection: %v", err)
	}
	if VerifyHello(key, n2, hello) != ErrHello {
		t.Error("a hello verified on another connection")
	}
	if VerifyHello(newKey(t).Public().(ed25519.PublicKey), n1, hello) != ErrHello {
		t.Error("a hello verified under another key")
	}
	otherDomain := ed25519.Sign(edge, append([]byte("agentos.edge.hello.v2\x00"), n1...))
	if VerifyHello(key, n1, otherDomain) != ErrHello {
		t.Error("a hello under another domain verified")
	}
	bare := ed25519.Sign(edge, n1)
	if VerifyHello(key, n1, bare) != ErrHello {
		t.Error("a signature over the bare nonce verified")
	}
	for _, body := range [][]byte{hello[:63], append(bytes.Clone(hello), 0), nil} {
		if VerifyHello(key, n1, body) != ErrHello {
			t.Errorf("a %d-byte hello verified", len(body))
		}
	}
	if VerifyHello(key, n1[:31], hello) != ErrHello || VerifyHello(key[:31], n1, hello) != ErrHello {
		t.Error("a short nonce or key was accepted")
	}

	// The message is fixed: the domain, then the 32-byte nonce.
	if !ed25519.Verify(key, append([]byte("agentos.edge.hello.v1\x00"), n1...), hello) {
		t.Error("the hello is not a signature over the domain and the nonce")
	}
	if _, err := SignHello(edge, n1[:31]); err != ErrHello {
		t.Errorf("SignHello with a short nonce: %v", err)
	}
	if _, err := HelloNonce(tls.ConnectionState{}); err != ErrHello {
		t.Errorf("HelloNonce of an incomplete handshake: %v", err)
	}
}
