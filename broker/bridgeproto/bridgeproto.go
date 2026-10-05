// Package bridgeproto is the modem bridge's contract with agentosd on
// owner.sock (P2-3w; CH-1, CH-2, ADP-12, ARC-2). The bridge (agentos-modem)
// drives the modems and is always the client: it hands agentosd each text
// it receives (OpInbound), pulls the texts agentosd sends (OpOutbox),
// reports each one's result as a fixed code (OpSent), and reports the
// lines' states as closed enums (OpState). agentosd links this package and
// nothing of the modem stack, so the ARC-2 fences hold.
//
// The bridge parses hostile input (any sender's PDUs, the provider's SIP),
// so nothing it says widens authority: agentosd builds the recipient of
// every owner text, stamps its own receive time, and maps states to its
// own fixed wording.
package bridgeproto

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Ops on owner.sock, beside "message" (the simulator's).
const (
	OpInbound = "inbound"
	OpOutbox  = "outbox"
	OpSent    = "sent"
	OpState   = "state"
)

// Refusals of an inbound text. The bridge sends a refused text again only
// while the refusal can pass (Retryable): paused until agentosd hears the
// line is ok, limited until the minute's count falls.
const (
	RefusedBad     = "bad inbound"
	RefusedSecond  = "second line not served"
	RefusedPaused  = "owner line paused"
	RefusedLimited = "inbound limited"
)

// Retryable says an inbound call that failed with err may be sent again:
// any failure but a refusal that cannot pass (bad text, second line).
func Retryable(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return !strings.HasSuffix(s, RefusedBad) && !strings.HasSuffix(s, RefusedSecond)
}

// Lines. The line a text arrived on, never its sender, decides whether it
// can reach the owner channel (security S-B8 on the P2-3w design).
const (
	LineOwner  = "owner"
	LineSecond = "second"
)

// Inbound is one text the bridge received.
type Inbound struct {
	Line string `json:"line"`
	From string `json:"from"`
	Text string `json:"text"`
	// Named: From is a sender name (TP-OA alphanumeric), not a number. It
	// is never the owner (CH-1).
	Named bool `json:"named,omitempty"`
	// ID names this text across the bridge's tries, so a try whose answer
	// was lost is not taken twice (a repeated approval code would count as
	// a wrong one). Up to MaxID characters; "" is never matched.
	ID string `json:"id,omitempty"`
}

// MaxID bounds Inbound.ID.
const MaxID = 64

// Limits on an Inbound (security S-B4): a text of at most MaxText bytes of
// UTF-8, a sender of at most MaxFrom printable characters.
const (
	MaxText = 1600
	MaxFrom = 32
)

// Valid says in is within the limits: a known line, a printable sender of
// at most MaxFrom characters (a number is + and digits), UTF-8 text of at
// most MaxText bytes.
func (in Inbound) Valid() bool {
	if in.Line != LineOwner && in.Line != LineSecond {
		return false
	}
	if len(in.ID) > MaxID || in.From == "" || len(in.From) > MaxFrom || !utf8.ValidString(in.Text) || len(in.Text) > MaxText {
		return false
	}
	for i, r := range in.From {
		switch {
		case in.Named:
			if r > unicode.MaxASCII || !unicode.IsPrint(r) {
				return false
			}
		case r == '+' && i == 0:
		case r < '0' || r > '9':
			return false
		}
	}
	return true
}

// Item is one text for the bridge to send. ID is single-use and
// unguessable (security S-B3); To is built by agentosd.
type Item struct {
	ID   string `json:"id"`
	Line string `json:"line"`
	To   string `json:"to"`
	Text string `json:"text"`
}

// OutboxWait is the longest an outbox poll waits for an item.
const OutboxWait = 25 * time.Second

// Sent is the result of an Item.
type Sent struct {
	ID   string `json:"id"`
	Code string `json:"code"`
}

// Result codes for Sent: CodeOK, or why the text did not go.
const (
	CodeOK          = "ok"
	CodeDown        = "down"
	CodeRecipient   = "recipient"
	CodeLimited     = "limited"
	CodeRefused     = "refused"
	CodeUnreachable = "unreachable"
	CodeTooLong     = "too_long"
)

// State is the lines' states, sent on each change and every minute.
type State struct {
	OwnerLine  string `json:"owner_line"`
	SecondLine string `json:"second_line,omitempty"`
}

// StateEvery is how often the bridge sends its state when nothing changed.
const StateEvery = time.Minute

// Line states. The owner line is ok, down (the modem does not answer),
// swapped (its SIM is not the one recorded at setup) or unbound (no SIM,
// or no number set up). Swapped and unbound stop the owner channel
// (security S-B8).
const (
	StateOK             = "ok"
	StateDown           = "down"
	StateSwapped        = "swapped"
	StateUnbound        = "unbound"
	StateUnregistered   = "unregistered"
	StateCarrierBlocked = "carrier_blocked"
)

// ValidOwnerLine says s is an owner-line state.
func ValidOwnerLine(s string) bool {
	switch s {
	case StateOK, StateDown, StateSwapped, StateUnbound:
		return true
	}
	return false
}
