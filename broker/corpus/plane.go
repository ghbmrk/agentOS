package corpus

import (
	"context"
	"errors"
	"strings"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/owner"
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
	// AutoReply hands text to the guest, has the guest compose it over
	// MCP as a reply in a thread the owner pre-allowed (ADP-11), and
	// reports what the broker did with it: queued as an auto-reply (the
	// commitment filter missed) or turned into a normal approval request
	// (it caught the text). Anything else the gate does with the reply,
	// such as refusing it because the thread is not verified, the machine
	// is not isolated or no rule matched, is an error, never a caught.
	AutoReply(ctx context.Context, text string) (queued bool, err error)
}

// PlaneChecks are the closed checks taken through r's guest: the code
// filter on the owner's line, the label check and the alert patterns on
// the mailbox, and the commitment filter on the grants gate's auto-reply
// (ADP-11, P3-4b-4e). Each keeps Checks' name and payload. Checks keeps
// its in-process copy of every check as a second probe: this one needs a
// guest machine (and runsc, in a box), so the in-process copy covers a
// box that runs without them. A text the owner's line would clip fails
// the code filter's run before the guest is asked: the clip could cut the
// code, so a missing code would be no verdict.
func PlaneChecks(r Relay) []loops.ClosedCheck {
	return []loops.ClosedCheck{
		{Name: CodeFilter, Payload: CodePayload, Deliver: func(ctx context.Context, s string) (bool, error) {
			if len(owner.AgentPrefix+s) > control.MaxText {
				return false, errOverOneText
			}
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
		{Name: CommitmentFilter, Payload: CommitmentPayload, Deliver: func(ctx context.Context, s string) (bool, error) {
			queued, err := r.AutoReply(ctx, s)
			return !queued, err
		}},
	}
}

var errOverOneText = errors.New("corpus: a replayed text is over one owner text")
