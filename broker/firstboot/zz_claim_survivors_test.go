package firstboot

// REQ: HW-10, HW-1

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/claim"
)

// Tests that pin the claim step's and Begin's error paths (mutgate on
// #6598).

// errLatch is the error unreadLatch's Load returns.
func errLatch() error { return errors.New("latch unreadable") }

// unreadLatch is a latch whose Load fails.
type unreadLatch struct{ change.MemStore }

func (*unreadLatch) Load() ([]byte, error) { return nil, errLatch() }

func claimCardConfig(t *testing.T) card.DisplayConfig {
	return card.DisplayConfig{Authority: testAuthority(t), Generate: card.Generate,
		Provision: func(*card.Card) error { return nil }}
}

// openSealed seals a new code into a memory store and opens its claim.
func openSealed(t *testing.T) (*claim.Claim, string) {
	t.Helper()
	b, code := sealedBox(t)
	cl, err := claim.Open(claim.Config{Store: &b.claim, BootID: func() (string, error) { return "boot-1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	return cl, code
}

// NewClaimedCard needs its config, and on a claimed box builds the card
// step at once, failing when it cannot.
func TestNewClaimedCardChecks(t *testing.T) {
	cfg := claimCardConfig(t)
	if _, err := NewClaimedCard(nil, &change.MemStore{}, cfg); err == nil {
		t.Fatal("no claim")
	}
	cl, code := openSealed(t)
	if _, err := cl.Try(code); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClaimedCard(cl, &unreadLatch{}, cfg); err == nil || err.Error() != errLatch().Error() {
		t.Fatalf("claimed box, unreadable latch: %v", err)
	}
}

// A card step that cannot start after the claim fails Claim with the token,
// and Hold and Again with the step's error; Reclaims follows the claim.
func TestAClaimWhoseCardCannotStart(t *testing.T) {
	cl, code := openSealed(t)
	cc, err := NewClaimedCard(cl, &unreadLatch{}, claimCardConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	const phone = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
	tok, err := cc.Claim(code, phone)
	if tok == "" || err == nil {
		t.Fatalf("claim: %q %v", tok, err)
	}
	if !cc.Reclaims(phone) || cc.Reclaims("") {
		t.Fatal("Reclaims is not the claim's")
	}
	if !cc.Claimant(tok) {
		t.Fatal("the token is not the claimant's")
	}
	if err := cc.Hold(); err == nil || err.Error() != errLatch().Error() {
		t.Fatalf("hold: %v", err)
	}
	if err := cc.Again(func() error { return nil }); err == nil || err.Error() != errLatch().Error() {
		t.Fatalf("again: %v", err)
	}
}

// Begin refuses an incomplete config, an unreadable latch, an unreadable
// claim state and a claim route whose card config is incomplete.
func TestBeginErrors(t *testing.T) {
	if _, err := Begin(BoxConfig{}); err == nil {
		t.Fatal("empty config")
	}
	b, _ := sealedBox(t)
	ok := func() error { return nil }
	boot := func() (string, error) { return "boot-1", nil }
	if _, err := Begin(BoxConfig{Claim: claim.Config{Store: &b.claim, BootID: boot}, Latch: &unreadLatch{},
		Reset: ok, Card: claimCardConfig(t)}); err == nil || err.Error() != errLatch().Error() {
		t.Fatalf("unreadable latch: %v", err)
	}
	if _, err := Begin(BoxConfig{Claim: claim.Config{Store: &unreadLatch{}, BootID: boot}, Latch: &change.MemStore{},
		Reset: ok, Card: claimCardConfig(t)}); err == nil || err.Error() != errLatch().Error() {
		t.Fatalf("unreadable claim state: %v", err)
	}
	if fb, err := Begin(BoxConfig{Claim: claim.Config{Store: &b.claim, BootID: boot}, Latch: &change.MemStore{},
		Reset: ok, Card: card.DisplayConfig{}}); err == nil {
		t.Fatalf("claim route without a provision: %+v", fb)
	}
}

// The reinstall route lets no phone claim again.
func TestReinstallReclaimsNothing(t *testing.T) {
	if (reinstall{}).Reclaims("c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3") {
		t.Fatal("reinstall re-claims")
	}
}
