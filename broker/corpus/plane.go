package corpus

import (
	"context"
	"strings"

	"github.com/ghbmrk/agentos/broker/loops"
)

// Relay takes a replayed text through a guest machine as untrusted input
// over its guest plane (ARC-6), down the path the real check sits on, and
// reports only what the broker itself then saw (P3-4b-4d). Nothing the
// guest says is a verdict: a guest that claims success, or says nothing,
// changes no answer here. A route returns an error when the broker did
// not see the guest carry text down it (a reply or request that is not
// the text handed over), so a guest that drops a text cannot pass as a
// check that caught it.
type Relay interface {
	// Reply hands text to the guest as an owner message, has the guest
	// answer the owner with it, and returns the text the owner's line
	// carried.
	Reply(ctx context.Context, text string) (sent string, err error)
	// Label hands text to the guest, has the guest ask over MCP to label
	// a mailbox message with it, and reports whether the mailbox message
	// carries a new label.
	Label(ctx context.Context, text string) (labelled bool, err error)
	// Archive plants text as outside mail in the inbox, has the guest ask
	// over MCP to archive it, and reports whether it left the inbox.
	Archive(ctx context.Context, text string) (hidden bool, err error)
}

// PlaneChecks are the closed checks taken through r's guest: the code
// filter on the owner's line, the label check and the alert patterns on
// the mailbox. Each keeps Checks' name and payload. The commitment filter
// is not among them: its route is the grants gate's auto-reply (ADP-11),
// so Checks' in-process copy stays its probe.
func PlaneChecks(r Relay) []loops.ClosedCheck {
	return []loops.ClosedCheck{
		{Name: CodeFilter, Payload: CodePayload, Deliver: func(ctx context.Context, s string) (bool, error) {
			sent, err := r.Reply(ctx, s)
			return !strings.Contains(sent, Code), err
		}},
		{Name: AlertPatterns, Payload: AlertPayload, Deliver: func(ctx context.Context, s string) (bool, error) {
			hidden, err := r.Archive(ctx, s)
			return !hidden, err
		}},
		{Name: LabelCheck, Payload: LabelPayload, Deliver: func(ctx context.Context, s string) (bool, error) {
			labelled, err := r.Label(ctx, s)
			return !labelled, err
		}},
	}
}
