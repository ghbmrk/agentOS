package control

import (
	"context"
	"strings"
	"testing"
)

// REQ: CH-11, CH-3, LOOP-0
//
// Whole-message settings (the loops') are answered by the broker in an
// unlocked session and never reach the agent; control words still win,
// and anything else is task chat.

func TestSettingsAreAnsweredBeforeTheAgent(t *testing.T) {
	agent := &recAgent{}
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, agent)
	var seen []string
	h.Settings = func(_ context.Context, msg string) (string, bool) {
		seen = append(seen, msg)
		if strings.EqualFold(msg, "loops off") {
			return "Spare-time work is off.", true
		}
		return "", false
	}
	if got := one(t, h.Handle(context.Background(), owner, "loops off")); got != "Spare-time work is off." || agent.text != "" {
		t.Fatalf("%q, agent got %q", got, agent.text)
	}
	h.Handle(context.Background(), owner, "book a table")
	if agent.text != "book a table" {
		t.Fatalf("task chat not delivered: %q", agent.text)
	}
	// Control words never reach the hook, and a PUBLIC task is task chat.
	h.Handle(context.Background(), owner, "STATUS")
	h.Handle(context.Background(), owner, "PUBLIC loops off")
	if len(seen) != 2 || agent.text != "loops off" || !agent.public {
		t.Fatalf("hook saw %q; agent got %q", seen, agent.text)
	}
}

func TestSettingsNeedAnUnlockedSession(t *testing.T) {
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: false}, forbiddenAgent{t})
	h.Settings = func(context.Context, string) (string, bool) {
		t.Fatal("a setting was tried in a locked session")
		return "", false
	}
	if got := one(t, h.Handle(context.Background(), owner, "LOOPS OFF")); got != unlockText {
		t.Fatalf("%q", got)
	}
}

func TestHelpCarriesTheExtraLine(t *testing.T) {
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, forbiddenAgent{t})
	h.HelpExtra = "LOOPS OFF/ON: spare-time work."
	if got := strings.Join(h.Handle(context.Background(), owner, "HELP"), ""); got != helpText+" "+h.HelpExtra {
		t.Fatalf("%q", got)
	}
}
