package clerkkey

// REQ: CLK-1

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/secret/secrettest"
)

// A clerk's key prints no key bytes, in sixteen verbs, bare and in holders
// with unexported pointer, value and interface fields (CLK-1, DECOY-b-8,
// #4833): a line that formats the kernel's hand-off to a clerk, or the
// clerk's own copy, puts no key in a log.
func TestKeyPrintsNoKey(t *testing.T) {
	var root [Len]byte
	for i := range root {
		root[i] = byte(0x61 + i)
	}
	k, err := Derive(&root, "mail")
	if err != nil {
		t.Fatal(err)
	}
	read, err := parse(must(Marshal(k)), "mail")
	if err != nil {
		t.Fatal(err)
	}
	b := k.Key.Get()
	secrettest.NoKey(t, [][]byte{b[:]}, append(secrettest.Holders(k), secrettest.Holders(read)...)...)
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
