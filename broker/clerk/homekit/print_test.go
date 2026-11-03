package homekit

// REQ: CLK-1

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The clerk's key holder and a session's frames print no key: not the
// controller's long-term key nor either direction's session key, in sixteen
// verbs (%w and %p included), bare and in holders with unexported pointer,
// value and interface fields (CLK-1, DECOY-b-8, #4837). Each sits in a
// handoff.Secret; the same key in a plain field shows, so the check can see
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
	type holder struct {
		k  *MemoryKeyHolder
		kv MemoryKeyHolder
		i  KeyHolder
		s  *Session
		c  *frameCipher
		cv frameCipher
		v  any
	}
	h := holder{kh, *kh, kh, s, wc, *wc, kh}
	secrets := [][]byte{seed, key}
	if keyShown(secrets, kh, *kh, s, wc, *wc, h, &h) {
		t.Error("the key holder or a session prints a key")
	}
	type plain struct{ k []byte }
	for _, p := range secrets {
		if !keyShown([][]byte{p}, &holder{v: &plain{p}}) {
			t.Errorf("no print showed %x in a plain field: the check cannot see it", p[:4])
		}
	}
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

// keyShown formats each of vs in sixteen verbs and reports whether any
// output holds a secret: raw, as hex, as decimal bytes, JSON-escaped or in
// the verb's own form of the bytes (handoff's TestKernelKeysPrintNoKey).
func keyShown(secrets [][]byte, vs ...any) bool {
	shown := false
	for _, v := range vs {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%t", "%e", "%c", "%U", "%o", "%b", "%w", "%p"} {
			out := strings.ToLower(fmt.Sprintf(verb, v))
			for _, s := range secrets {
				j, _ := json.Marshal(string(s))
				for _, f := range []string{string(s), hex.EncodeToString(s), strings.Trim(fmt.Sprint(s), "[]"), strings.Trim(string(j), `"`), strings.Trim(fmt.Sprintf(verb, s), "[]")} {
					shown = shown || len(f) >= 10 && strings.Contains(out, strings.ToLower(f))
				}
			}
		}
	}
	return shown
}
