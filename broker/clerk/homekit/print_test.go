package homekit

// REQ: CLK-1

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
)

// The clerk's key holder and a session's frames print no key: not the
// controller's long-term key nor either direction's session key, in sixteen
// verbs (%w and %p included), bare and in holders with unexported pointer,
// value and interface fields (CLK-1, DECOY-b-8, #4837). Each sits in a
// secret.Secret; the same key in a plain field shows, so the check can see
// one. Catches an error or debug line that formats a holder or a session
// and puts its key in a log.
func TestKeyHolderAndSessionPrintNoKey(t *testing.T) {
	seed := bytes.Repeat([]byte{0x5c, 0x3d}, ed25519.SeedSize/2)
	kh, err := NewMemoryKeyHolder("5A1C0DE5-0000-4000-8000-00000000BEEF", seed)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x7a, 0x19}, 16)
	wc, _ := newFrameCipher(key)
	rc, _ := newFrameCipher(key)
	s := &Session{w: &frameWriter{w: &bytes.Buffer{}, c: wc}, br: bufio.NewReaderSize(&frameReader{r: &bytes.Buffer{}, c: rc}, readBufSize)}
	vs := append(secrettest.Holders(kh), secrettest.Holders(*kh)...)
	vs = append(vs, secrettest.Holders(KeyHolder(kh))...)
	vs = append(vs, secrettest.Holders(s)...)
	vs = append(vs, secrettest.Holders(wc)...)
	vs = append(vs, secrettest.Holders(*wc)...)
	secrettest.NoKey(t, [][]byte{seed, key}, vs...)
	// The holder still signs with its key, and a frame sealed with one
	// cipher opens with the other.
	if !ed25519.Verify(kh.PublicKey(), []byte("m"), must(kh.Sign([]byte("m")))) ||
		!bytes.Equal(kh.PublicKey(), ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)) {
		t.Error("the holder lost its key")
	}
	var wire bytes.Buffer
	if _, err := (&frameWriter{w: &wire, c: wc}).Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if b, err := bufio.NewReader(&frameReader{r: &wire, c: rc}).Peek(5); err != nil || string(b) != "hello" {
		t.Errorf("frame round trip: %q %v", b, err)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
