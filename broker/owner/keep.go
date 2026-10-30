package owner

import (
	"fmt"
	"log"

	"github.com/ghbmrk/agentos/broker/control"
)

// Keeper keeps a withheld text for the owner page, durably, before the
// channel points to it (CH-19, CH-21, #993). kind is KeptSecret,
// KeptOneTime or KeptCode; text is stripped of controls. An error means it was not kept.
type Keeper interface {
	Keep(kind, text string) error
}

// The kinds of text the channel withholds and keeps.
const (
	KeptSecret  = "secret"  // CH-19: may carry a key
	KeptOneTime = "onetime" // CH-19: carries a code and no key; the code is kept for hours (#906)
	KeptCode    = "code"    // CH-21: mentions a code or takes the reply grammar
)

// Where a withheld text came from, as the channel itself knows it: the
// agent, or the broker's own text. Neither is a display name (CH-19).
const (
	fromAgent  = "a message from your agent"
	fromNotice = "one of my notices"
)

// CodePointer replaces a withheld text whose only secret is a code, once
// it is kept: it names the kind of code (CodeKind) and the source, never
// the value (CH-19, #906).
func CodePointer(kind, source string) string {
	return "I held back " + kind + " in " + source + ". Read it on my Wi-Fi page."
}

// codePointers are every CodePointer the channel can send, so withheld
// knows them exactly.
var codePointers = func() map[string]bool {
	m := map[string]bool{}
	for _, src := range []string{fromAgent, fromNotice} {
		m[CodePointer("a code", src)] = true
		for n := 4; n <= 10; n++ {
			m[CodePointer(fmt.Sprintf("a code of %d digits", n), src)] = true
		}
	}
	return m
}()

// SetKeeper sets what keeps withheld text. Until it is set, and whenever
// it fails, the channel sends the could-not-be-kept text, which names no
// page (CH-19, D-079). Set it only when the owner page can show what it
// keeps (CH-12).
func (c *Channel) SetKeeper(k Keeper) {
	c.keeper.Store(&k)
}

// withhold keeps agent text of kind for the owner page and returns the
// pointer to send, or, when it was not kept, the text saying so.
func (c *Channel) withhold(kind, text string) string {
	return c.withholdFrom(kind, text, fromAgent)
}

// withholdFrom is withhold for text from source. Secret-shaped text that
// carries a code and no key is kept as KeptOneTime, and its pointer names
// the code's kind and the source (CH-19, #906). The log names only the
// kind: the text may carry the code.
func (c *Channel) withholdFrom(kind, text, source string) string {
	text = control.StripControls(text)
	pointer, notKept := HiddenPointer, Hidden
	switch {
	case kind == KeptCode:
		pointer, notKept = HeldCodePointer, HeldCode
	case kind == KeptSecret && AgentCode(text) && !AgentToken(text):
		kind, pointer = KeptOneTime, CodePointer(CodeKind(text), source)
	}
	if k := c.keeper.Load(); k != nil && (*k).Keep(kind, text) == nil {
		return pointer
	}
	log.Printf("owner channel: a held %s text was not kept for the owner page", kind)
	return notKept
}

// disclose is Disclose for the channel's own texts: secret-shaped text is
// kept, then pointed to (withholdFrom).
func (c *Channel) disclose(s string) string {
	if SecretShaped(s) {
		return c.withholdFrom(KeptSecret, s, fromNotice)
	}
	return s
}

// withheld reports whether text is one of the texts that stand in for a
// withheld one, which go without AgentPrefix.
func withheld(text string) bool {
	return text == Hidden || text == HiddenPointer || text == HeldCode || text == HeldCodePointer || codePointers[text]
}
