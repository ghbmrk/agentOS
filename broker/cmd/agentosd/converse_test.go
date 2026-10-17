package main

import (
	"strings"
	"testing"

	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-15
// An agent reply from the evidence outbox, wired as evidence.attach wires
// it, is conversation: in quiet hours it goes at once behind the agent
// prefix, and with no owner channel yet it fails rather than sends.
func TestAgentReplyIsConversation(t *testing.T) {
	r := pacedOwner(t, quiet22to7(), at23)
	ev := &evidence{notify: converse(func() *ownerch.Channel { return r.ch }), logf: t.Logf}
	ev.send("agent", "Your invoice is drafted.")
	if got := r.sent(); len(got) != 1 || got[0] != ownerch.AgentPrefix+"Your invoice is drafted." {
		t.Fatalf("agent reply in quiet hours: %q, want it sent at once", got)
	}
	if err := converse(func() *ownerch.Channel { return nil })("x"); err == nil || !strings.Contains(err.Error(), "no owner channel") {
		t.Fatalf("no channel: %v", err)
	}
}
