package main

// REQ: EVL-2

import (
	"crypto/ed25519"
	"math/rand/v2"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A plan's rejection code is the one its own rejection logged; a plan the
// log never rejected has none, not another plan's (#6023).
func TestARejectionCodeIsThePlansOwn(t *testing.T) {
	head := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: head.Public().(ed25519.PublicKey), Sign: head,
		Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.Boot(l, nil, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := make([]byte, ed25519.SeedSize)
	s[0] = 1
	stranger := ed25519.NewKeyFromSeed(s)
	root := key.Issue(key.Ed25519Signer(stranger), key.Root{Clerk: inbox.Name, Verbs: []key.Verb{key.Trash}, Serial: "s"})
	p := kernel.SignPlan(kernel.Plan{ID: "x", Key: root, Steps: []kernel.PlanStep{{Verb: key.Trash, Clerk: inbox.Name, Args: map[string]string{"target": "m"}}}}, stranger)
	if err := k.Submit(0, p); err != nil {
		t.Fatal(err)
	}
	want := k.State().Plans["x"].Reject
	if want.IsZero() {
		t.Fatalf("the stranger's plan is %s", k.State().Plans["x"].Status)
	}
	if c := rejectionCode(k, "x"); c != want {
		t.Fatalf("code %v, want %v", c, want)
	}
	if c := rejectionCode(k, "never"); !c.IsZero() {
		t.Fatalf("a plan never rejected: code %v", c)
	}
}
