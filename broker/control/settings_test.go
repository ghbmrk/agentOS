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
	h.Settings = func(_ context.Context, msg string, _ bool) (string, bool) {
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

// UX-57-1, CH-11: a locked session still takes a pause-only setting; the
// rest get the unlock prompt and never reach the agent.
func TestALockedSessionTakesOnlyPauses(t *testing.T) {
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: false}, forbiddenAgent{t})
	h.Settings = func(_ context.Context, msg string, unlocked bool) (string, bool) {
		if unlocked {
			t.Fatal("told unlocked in a locked session")
		}
		if msg == "LOOPS OFF" {
			return "Spare-time work is off.", true
		}
		return "", false
	}
	if got := one(t, h.Handle(context.Background(), owner, "LOOPS OFF")); got != "Spare-time work is off." {
		t.Fatalf("%q", got)
	}
	if got := one(t, h.Handle(context.Background(), owner, "LOOPS ON")); got != unlockText {
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

// UX-90-1: a setting that starts with STOP (STOP SHARING) gets only its
// own reply, not the STOP hint, and leaves the hourly hint for a real
// near-miss.
func TestASettingIsNotAStopNearMiss(t *testing.T) {
	agent := &recAgent{}
	h, _ := newHandler(t, &fakeEngine{}, fakeAuth{unlocked: true}, agent)
	h.Settings = func(_ context.Context, msg string, _ bool) (string, bool) {
		if msg == "STOP SHARING" {
			return "Sharing is off.", true
		}
		return "", false
	}
	if got := one(t, h.Handle(context.Background(), owner, "STOP SHARING")); got != "Sharing is off." {
		t.Fatalf("%q", got)
	}
	if out := h.Handle(context.Background(), owner, "STOP NOW"); len(out) == 0 || out[0] != stopHint {
		t.Fatalf("near-miss after a setting: %q", out)
	}
}
