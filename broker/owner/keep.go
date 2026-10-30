package owner

import (
	"log"

	"github.com/ghbmrk/agentos/broker/control"
)

// Keeper keeps a withheld text for the owner page, durably, before the
// channel points to it (CH-19, CH-21, #993). kind is KeptSecret or
// KeptCode; text is stripped of controls. An error means it was not kept.
type Keeper interface {
	Keep(kind, text string) error
}

// The kinds of text the channel withholds and keeps.
const (
	KeptSecret = "secret" // CH-19: may carry a code or key
	KeptCode   = "code"   // CH-21: mentions a code or takes the reply grammar
)

// SetKeeper sets what keeps withheld text. Until it is set, and whenever
// it fails, the channel sends the could-not-be-kept text, which names no
// page (CH-19, D-079). Set it only when the owner page can show what it
// keeps (CH-12).
func (c *Channel) SetKeeper(k Keeper) {
	c.keeper.Store(&k)
}

// withhold keeps text of kind for the owner page and returns the pointer
// to send, or, when it was not kept, the text saying so. The log names
// only the kind: the text may carry the code.
func (c *Channel) withhold(kind, text string) string {
	pointer, notKept := HiddenPointer, Hidden
	if kind == KeptCode {
		pointer, notKept = HeldCodePointer, HeldCode
	}
	if k := c.keeper.Load(); k != nil && (*k).Keep(kind, control.StripControls(text)) == nil {
		return pointer
	}
	log.Printf("owner channel: a held %s text was not kept for the owner page", kind)
	return notKept
}

// disclose is Disclose for the channel's own texts: secret-shaped text is
// kept, then pointed to (withhold).
func (c *Channel) disclose(s string) string {
	if SecretShaped(s) {
		return c.withhold(KeptSecret, s)
	}
	return s
}

// withheld reports whether text is one of the texts that stand in for a
// withheld one, which go without AgentPrefix.
func withheld(text string) bool {
	return text == Hidden || text == HiddenPointer || text == HeldCode || text == HeldCodePointer
}
