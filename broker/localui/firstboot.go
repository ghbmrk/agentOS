package localui

import (
	"context"
	"errors"
	"sync"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/claim"
	"github.com/ghbmrk/agentos/broker/firstboot"
)

// ReasonCodesUnconfirmed is the vault process's reason on /card/provision's
// refusal for a code generator nobody confirmed (egress K21): the setup
// vault was made anew, so the owner sets up the code generator again (F10).
const ReasonCodesUnconfirmed = "codes_unconfirmed"

// ErrCodesUnconfirmed is wrapped by an UnlockClient error whose reply
// carries ReasonCodesUnconfirmed.
var ErrCodesUnconfirmed = errors.New("vault: no code generator is confirmed")

// CodesVoid is set when the vault's code generator entry no longer counts
// (F10, #1210 R1): a card provision refused with ReasonCodesUnconfirmed, or
// a card reset that made the setup vault anew. Setup takes it and sends
// the owner back to the codes step.
type CodesVoid struct {
	mu  sync.Mutex
	set bool
}

// Set marks the code generator void.
func (v *CodesVoid) Set() {
	v.mu.Lock()
	v.set = true
	v.mu.Unlock()
}

// Take reports whether the code generator was marked void since the last
// Take, and clears the mark.
func (v *CodesVoid) Take() bool {
	if v == nil {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	was := v.set
	v.set = false
	return was
}

// CardBox is the page's first-boot config (#1115): the card step's
// provision and the unconfirmed card's reset go to the vault process over
// the unlock socket (egress K21, K22), and either answer that voids the
// code generator sets void. claimStore holds the claim state a seller
// sealed (claim.StatePath); latch is the card step's latch. authority is
// the page authority's certificate (PageTLS.Authority), which the card
// prints; nil holds the card step (firstboot.ErrNoAuthority, HW-1).
// The confirm hands the card's factors to keeper first (handOff, brief
// OWN-card-flow decision 9); only after its ok does it provision the vault,
// whose failure the page retries with the same card, which the keeper
// answers ok again. The vault call goes with the vault's deletion row.
func CardBox(u *UnlockClient, keeper CardKeeper, claimStore claim.Store, latch firstboot.Store, void *CodesVoid, authority []byte) firstboot.BoxConfig {
	return firstboot.BoxConfig{
		Claim: claim.Config{Store: claimStore},
		Latch: latch,
		Reset: func() error {
			ctx, cancel := context.WithTimeout(context.Background(), commitTimeout)
			defer cancel()
			remade, err := u.ResetCard(ctx)
			if remade {
				void.Set()
			}
			return err
		},
		Card: card.DisplayConfig{Authority: authority, Provision: func(c *card.Card) error {
			if err := handOff(keeper, c, authority); err != nil {
				return err
			}
			// A background context with a limit, as the rotation's
			// commit (L38): a phone that drops mid-provision cannot cut
			// a slot write short.
			ctx, cancel := context.WithTimeout(context.Background(), commitTimeout)
			defer cancel()
			err := u.ProvisionCard(ctx, c)
			if errors.Is(err, ErrCodesUnconfirmed) {
				void.Set()
			}
			return err
		}},
	}
}
