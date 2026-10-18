package firstboot

import (
	"errors"
	"fmt"
	"sync"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/claim"
)

// ErrUnclaimed is what ClaimedCard.Hold returns until a phone has claimed
// the box with its sticker code (HW-10).
var ErrUnclaimed = errors.New("firstboot: I am waiting to be claimed")

// ClaimedCard is a preloaded box's first-boot path (HW-10): the Owner Card
// step does not exist until the box is claimed, so no card, vault key or
// approval-code seed is generated before the claim (HW-1). On a claimed
// box it is the card step.
type ClaimedCard struct {
	cl  *claim.Claim
	st  Store
	cfg card.DisplayConfig

	mu   sync.Mutex
	step *CardStep
}

// NewClaimedCard builds the card step at once on a claimed box, and only
// at the claim otherwise. st and cfg are NewCardStep's.
func NewClaimedCard(cl *claim.Claim, st Store, cfg card.DisplayConfig) (*ClaimedCard, error) {
	if cl == nil || st == nil || cfg.Provision == nil {
		return nil, errors.New("firstboot: incomplete claim step config")
	}
	c := &ClaimedCard{cl: cl, st: st, cfg: cfg}
	if cl.Claimed() {
		if _, err := c.card(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// card builds the card step once the box is claimed; nil before.
func (c *ClaimedCard) card() (*CardStep, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.step != nil || !c.cl.Claimed() {
		return c.step, nil
	}
	s, err := NewCardStep(c.st, c.cfg)
	if err != nil {
		return nil, err
	}
	c.step = s
	return s, nil
}

// Status is the claim screen's state.
func (c *ClaimedCard) Status() claim.Status { return c.cl.Status() }

// Claim presents a sticker code. On the claim it returns the claiming
// phone's token and starts the card step. If the card step cannot start,
// the box is claimed all the same and the token is returned with the
// error: Card and Hold retry it.
func (c *ClaimedCard) Claim(code string) (string, error) {
	tok, err := c.cl.Try(code)
	if err != nil {
		return "", err
	}
	if _, err := c.card(); err != nil {
		return tok, fmt.Errorf("firstboot: claimed, but the card step did not start: %w", err)
	}
	return tok, nil
}

// Claimant reports whether tok names the phone that claimed the box: only
// it is shown the Owner Card and continues setup.
func (c *ClaimedCard) Claimant(tok string) bool { return c.cl.Claimant(tok) }

// Card is the card step: nil before the claim.
func (c *ClaimedCard) Card() *CardStep {
	s, _ := c.card()
	return s
}

// Display is the card step's display for the local page: nil before the
// claim and after the confirm (localui.OwnerCard).
func (c *ClaimedCard) Display() *card.Display {
	if s := c.Card(); s != nil {
		return s.Display()
	}
	return nil
}

// Hold returns ErrUnclaimed until the claim, then the card step's Hold.
func (c *ClaimedCard) Hold() error {
	if !c.cl.Claimed() {
		return fmt.Errorf("%w: scan or type the claim code on my sticker", ErrUnclaimed)
	}
	s, err := c.card()
	if err != nil {
		return err
	}
	return s.Hold()
}

// Again reruns the card step (CardStep.Again); ErrUnclaimed before the
// claim.
func (c *ClaimedCard) Again(reset func() error) error {
	if !c.cl.Claimed() {
		return fmt.Errorf("%w: scan or type the claim code on my sticker", ErrUnclaimed)
	}
	s, err := c.card()
	if err != nil {
		return err
	}
	return s.Again(reset)
}
