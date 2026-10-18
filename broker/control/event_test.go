package control

import (
	"context"
	"testing"
)

// REQ: CH-11

// A reaction event reaches the agent only as a task message would: from
// the owner, in an unlocked session, never through the Settings or Answer
// hooks; a down agent gets the agent-down text.
func TestEventGoesAsTaskChatDoes(t *testing.T) {
	const ev = "Owner reaction: liked your text \"Lunch is booked.\""
	agent := &recAgent{}
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, agent)
	h.Settings = func(context.Context, string, bool) (string, bool) {
		t.Fatal("event reached Settings")
		return "", false
	}
	h.Answer = func(context.Context, string) (string, bool) { t.Fatal("event reached Answer"); return "", false }
	if out := h.Event(context.Background(), owner, ev); len(out) != 0 || agent.text != ev || agent.public {
		t.Fatalf("Event = %q, agent got %q (public %v)", out, agent.text, agent.public)
	}
	h, _ = newHandler(t, &fakeEngine{}, fakeAuth{unlocked: false}, forbiddenAgent{t})
	if got := one(t, h.Event(context.Background(), owner, ev)); got != unlockText {
		t.Fatalf("locked Event = %q", got)
	}
	h, _ = newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, forbiddenAgent{t})
	if out := h.Event(context.Background(), "+15550000000", ev); out != nil {
		t.Fatalf("stranger Event = %q", out)
	}
	h, _ = newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, &downAgent{})
	if got := one(t, h.Event(context.Background(), owner, ev)); got != agentDown {
		t.Fatalf("down Event = %q", got)
	}
}
