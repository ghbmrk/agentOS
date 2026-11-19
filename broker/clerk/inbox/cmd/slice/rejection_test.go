package main

// REQ: EVL-2

import (
	"crypto/ed25519"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// A plan the log never rejected has no rejection code: the zero Code, not
// another plan's (#6023).
func TestNoRejectionNoCode(t *testing.T) {
	s := make([]byte, ed25519.SeedSize)
	p := ed25519.NewKeyFromSeed(s)
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: p.Public().(ed25519.PublicKey), Sign: p})
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.Boot(l, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if c := rejectionCode(k, "never"); !c.IsZero() {
		t.Fatalf("code %v", c)
	}
}
