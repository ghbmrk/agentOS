package edgelink

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
)

// The hello (decision 5 of briefs/EDGE-link-core.md): an edge whose key is
// not live proves it holds that key on this connection, so the core can
// report it as a candidate. Its body is the edge key's Ed25519 signature
// over HelloDomain followed by the connection's exporter value; the
// exporter is fresh per handshake and bound to it, so a hello never
// replays onto another connection, and {key, nonce, signature} is enough
// for the kernel to check it again on replay.
const (
	HelloDomain        = "agentos.edge.hello.v1\x00"
	HelloExporterLabel = "agentos edge hello"
	NonceLen           = 32
	HelloLen           = ed25519.SignatureSize
)

// ErrHello is every hello refusal.
var ErrHello = errors.New("edgelink: hello does not verify")

// HelloNonce is the connection's exporter value, the hello's nonce. Both
// ends of one connection compute the same value.
func HelloNonce(cs tls.ConnectionState) ([]byte, error) {
	if !cs.HandshakeComplete || cs.Version != tls.VersionTLS13 {
		return nil, ErrHello
	}
	return cs.ExportKeyingMaterial(HelloExporterLabel, nil, NonceLen)
}

// SignHello is the edge's side: signer's signature over the hello for
// nonce.
func SignHello(signer crypto.Signer, nonce []byte) ([]byte, error) {
	if _, ok := signer.Public().(ed25519.PublicKey); !ok || len(nonce) != NonceLen {
		return nil, ErrHello
	}
	sig, err := signer.Sign(rand.Reader, helloMessage(nonce), crypto.Hash(0))
	if err != nil || len(sig) != HelloLen {
		return nil, ErrHello
	}
	return sig, nil
}

// VerifyHello checks a hello body against the key the handshake presented
// and this connection's nonce.
func VerifyHello(key ed25519.PublicKey, nonce, body []byte) error {
	if len(key) != ed25519.PublicKeySize || len(nonce) != NonceLen || len(body) != HelloLen {
		return ErrHello
	}
	if !ed25519.Verify(key, helloMessage(nonce), body) {
		return ErrHello
	}
	return nil
}

func helloMessage(nonce []byte) []byte {
	return append([]byte(HelloDomain), nonce...)
}
