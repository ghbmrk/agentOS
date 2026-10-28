package proc

// REQ: CLK-2, UPD-3

import (
	"crypto/ed25519"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A clerk process's view of a plan under the image-pinned root carries that
// root's grant, so the update clerk's own check passes; the kernel's anchors
// alone verify no such plan, so a view built without the pinned roots
// carries none (#3677).
func TestViewCarriesThePinnedRoot(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 40
	image := ed25519.NewKeyFromSeed(seed)
	up := key.Issue(key.Ed25519Signer(image), key.Root{Clerk: "update", Verbs: []key.Verb{key.ChangeAccount}, Serial: "image"})
	s := kernel.NewState(nil)
	if err := s.Pin(up); err != nil {
		t.Fatal(err)
	}
	p := kernel.SignPlan(kernel.Plan{ID: "a1", Key: up, Steps: []kernel.PlanStep{{Verb: key.ChangeAccount, Clerk: "update",
		Args: map[string]string{"target": "usr", "value": "entry"}}}}, image)
	r := kernel.Request{Plan: p}
	if v := view(s, s.Anchors, s.Pinned(), r, 1); v.Grants[up.Tip()] != 0 || len(v.Grants) != 1 {
		t.Fatalf("pinned view grants %v", v.Grants)
	}
	if v := view(s, s.Anchors, nil, r, 1); len(v.Grants) != 0 {
		t.Fatalf("view without the pinned roots grants %v", v.Grants)
	}
}
