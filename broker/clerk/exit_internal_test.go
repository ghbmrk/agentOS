package clerk

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A clerk's TLS handshake gives up after ten seconds, so a remote that
// accepts the connection and never answers cannot hold a step open.
func TestGuardedTransportBoundsTheHandshake(t *testing.T) {
	tr := guarded(nil, nil).Transport.(*http.Transport)
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Fatalf("TLS handshake timeout %v, want 10s", tr.TLSHandshakeTimeout)
	}
}

// A declared shape names every body field and the slot it sends; an empty
// field name or a slot the store does not hold is refused at declaration.
func TestShapeRefusesAnEmptyBodyFieldAndAMissingSlot(t *testing.T) {
	names := []string{"id"}
	if _, err := shape(Op{Method: "POST", URL: "https://h.test/x", Type: TypeJSON, Body: map[string]string{"": "id"}}, "v", names, nil); err == nil {
		t.Error("an empty body field was declared")
	}
	if _, err := shape(Op{Method: "GET", URL: "https://h.test/x", Slot: "s"}, "v", names, nil); err == nil {
		t.Error("a slot the store does not hold was declared")
	}
}

// A verb the exit does not declare has no facts and is refused as
// undeclared, whatever arguments its step carries.
func TestExitUndeclaredVerbHasNoFactsAndIsRefused(t *testing.T) {
	x := &Exit{ops: map[key.Verb]decl{}}
	content, labels, amount := x.Facts(key.Step{Verb: key.Trash, Args: map[string]key.Arg{key.ArgAmount: {Value: "5"}}})
	if content != "" || labels != nil || amount != 0 {
		t.Errorf("undeclared verb read as %q %v %d", content, labels, amount)
	}
	if r := x.Do(kernel.Request{}, nil); r.Outcome != "failed" || r.Detail != DUndeclared {
		t.Errorf("undeclared verb answered %+v", r)
	}
}

// openAny opens every blob, the empty one included, as the plaintext "x".
type openAny struct{}

func (openAny) Seal(plain, _ []byte) ([]byte, error) { return plain, nil }
func (openAny) Open([]byte, []byte) ([]byte, error)  { return []byte("x"), nil }

// A slot the store does not hold opens nothing, even under a sealer that
// would open an empty blob; a nil store holds no slot.
func TestSecretsMissingSlotNeverReachesTheSealer(t *testing.T) {
	called := false
	err := NewSecrets(openAny{}, nil).with("absent", KindStatic, func([]byte) error { called = true; return nil })
	if err == nil || called {
		t.Fatalf("a missing slot opened: err %v, called %v", err, called)
	}
	if (*Secrets)(nil).Has("absent") {
		t.Fatal("a nil store holds a slot")
	}
}

// The AES sealer takes only a 32-byte key, draws a fresh nonce for every
// seal, and refuses a blob shorter than its nonce without reading past it.
func TestAESSealerKeyNonceAndShortBlob(t *testing.T) {
	if _, err := NewAESSealer(make([]byte, 16)); err == nil {
		t.Fatal("a 16-byte key was taken")
	}
	s, err := NewAESSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Seal([]byte("p"), nil)
	b, _ := s.Seal([]byte("p"), nil)
	n := s.(aesSealer).g.NonceSize()
	if bytes.Equal(a[:n], b[:n]) || bytes.Equal(a[:n], make([]byte, n)) {
		t.Fatalf("nonces %x and %x: not fresh", a[:n], b[:n])
	}
	if _, err := s.Open(a[:n-1], nil); err == nil || err.Error() != "clerk: sealed secret too short" {
		t.Fatalf("a blob shorter than the nonce: %v", err)
	}
	// A blob of exactly the nonce reaches GCM, which refuses it as unauthentic.
	if _, err := s.Open(a[:n], nil); err == nil || err.Error() != "cipher: message authentication failed" {
		t.Fatalf("a blob of only the nonce: %v", err)
	}
}
