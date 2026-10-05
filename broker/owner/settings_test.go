package owner

import (
	"context"
	"strings"
	"testing"
)

// REQ: LOOP-0, CH-11, CH-14

// fakeSettings stands in for the loop scheduler's settings hook: "LOOPS
// OFF" narrows, "LOOPS ON" does not.
type fakeSettings struct{ got []string }

func (f *fakeSettings) text(_ context.Context, msg string, unlocked bool) (string, bool) {
	switch strings.ToUpper(msg) {
	case "LOOPS OFF":
		f.got = append(f.got, msg)
		return "Spare-time work is off.", true
	case "LOOPS ON":
		if !unlocked {
			return "", false
		}
		f.got = append(f.got, msg)
		return "Spare-time work is on.", true
	}
	return "", false
}

func (f *fakeSettings) narrows(msg string) bool { return strings.EqualFold(msg, "LOOPS OFF") }

// The owner channel hands whole-message settings to the settings hook, and
// HELP carries its line. A narrowing setting runs at once in a locked
// session, like a pause word (CH-11); one that widens is held for the
// unlock like any other message (CH-14).
func TestSettingsReachTheHookAndNarrowingSkipsTheLock(t *testing.T) {
	f := &fakeSettings{}
	r := newRig(t, nil)
	r.edit = func(c *Config) {
		c.Settings, c.Narrows, c.HelpExtra = f.text, f.narrows, "LOOPS OFF/ON: spare-time work."
	}
	r.ch = r.open()

	if got := r.say("LOOPS OFF"); got != "Spare-time work is off." {
		t.Fatalf("locked LOOPS OFF: %q", got)
	}
	if got := r.say("LOOPS ON"); !strings.HasPrefix(got, "Locked.") {
		t.Fatalf("locked LOOPS ON: %q", got)
	}
	if len(f.got) != 1 {
		t.Fatalf("hook got %q while locked", f.got)
	}
	if n := len(r.agent.got()); n != 0 {
		t.Fatalf("a setting reached the agent: %d", n)
	}
	r.unlock()
	if got := r.say("LOOPS ON"); got != "Spare-time work is on." {
		t.Fatalf("unlocked LOOPS ON: %q", got)
	}
	if got := r.say("HELP"); !strings.Contains(got, "LOOPS OFF/ON: spare-time work.") {
		t.Fatalf("HELP: %q", got)
	}
}
