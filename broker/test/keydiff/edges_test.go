package keydiff

// REQ: KEY-1

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// TestEd25519EdgeVectors checks the Go side of the edge vectors keycheck's
// own tests also check (#3357): malleable S, small- and mixed-order points and
// non-canonical encodings, each with its expected verdict. The sweep only
// flips signature bits, so without these a Go or dalek bump that changed how
// one of them verifies would pass unseen. Both the holder's check
// (crypto/ed25519.Verify) and a passkey's (key.PublicKey.Verify) must agree.
// It needs no keycheck binary.
func TestEd25519EdgeVectors(t *testing.T) {
	f, err := os.Open("../../../assurance/keycheck/testdata/ed25519-edges.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n, admitted := 0, 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Split(line, " ")
		if len(fs) != 5 || (fs[4] != "true" && fs[4] != "false") {
			t.Fatalf("malformed vector %q", line)
		}
		var b [3][]byte
		for i := range b {
			if b[i], err = hex.DecodeString(fs[i+1]); err != nil {
				t.Fatalf("%s: %v", fs[0], err)
			}
		}
		want := fs[4] == "true"
		if got := ed25519.Verify(ed25519.PublicKey(b[0]), b[1], b[2]); got != want {
			t.Errorf("%s: ed25519.Verify = %v, want %v", fs[0], got, want)
		}
		if got := key.Ed25519(b[0]).Verify(b[1], b[2]); got != want {
			t.Errorf("%s: key.PublicKey.Verify = %v, want %v", fs[0], got, want)
		}
		n++
		if want {
			admitted++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 25 || admitted != 14 {
		t.Fatalf("read %d vectors, %d admitted; want 25 and 14", n, admitted)
	}
}
