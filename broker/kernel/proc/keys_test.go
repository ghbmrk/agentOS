package proc

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"testing"
)

func gen(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	p := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	return p.Public().(ed25519.PublicKey), p
}

// The owner's two hardware keys (D-146), the clerk key's holder and the
// log's head key, as broker/clerk/run's tests make them.
var (
	ownerPub, ownerPriv   = gen(1)
	holderPub, holderPriv = gen(2)
	headPub, headPriv     = gen(3)
	sparePub, sparePriv   = gen(4)
	anchors               = []ed25519.PublicKey{ownerPub, sparePub}
)

// shortDir is a temporary directory with a short path: a socket's path must
// fit in 108 bytes, which a test's own TempDir under a long name may not.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "run")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}
