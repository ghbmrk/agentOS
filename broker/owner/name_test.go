package owner

// REQ: CH-21, CH-11, A14

import (
	"regexp"
	"strings"
	"testing"
)

var nameCodeRe = regexp.MustCompile(`To confirm, reply NAME ([0-9]{6}) within 15 min\.$`)

// named opens a rig whose owner's name is known.
func named(t *testing.T) *rig {
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.OwnerName = "Mark Jones" }
	r.ch = r.open()
	return r
}

// TestNameAloneRepliesWithTheCurrentName: NAME alone answers with the
// box's name, in any session (CH-11).
func TestNameAloneRepliesWithTheCurrentName(t *testing.T) {
	r := named(t)
	if got := r.say("name"); got != "I have no name yet. To give me one, send NAME and the name." {
		t.Fatalf("no name: %q", got)
	}
	if got := r.say("NAME Dave Smith " + r.totp()); got != `Done. My name is now "Dave Smith".` {
		t.Fatalf("rename: %q", got)
	}
	if got := r.say("Name?"); got != `My name is "Dave Smith".` {
		t.Fatalf("name: %q", got)
	}
	if n := r.ch.Name(); n != "Dave Smith" {
		t.Fatalf("Name() = %q", n)
	}
	// It survives a restart.
	r.ch = r.open()
	if n := r.ch.Name(); n != "Dave Smith" {
		t.Fatalf("after restart: %q", n)
	}
	if got := r.agent.got(); len(got) != 0 {
		t.Fatalf("agent got %q", got)
	}
}

// TestNameWithCodeGeneratorCodeRenamesAtOnce: a code-generator code in
// the NAME message proves the owner wrote it, so the rename takes effect,
// confirmed in fixed wording; a wrong one renames nothing and counts.
func TestNameWithCodeGeneratorCodeRenamesAtOnce(t *testing.T) {
	r := named(t)
	if got := r.say("NAME Evil Twin 000000"); !strings.HasPrefix(got, "Wrong code. Nothing changed.") {
		t.Fatalf("wrong code: %q", got)
	}
	if n := r.ch.Name(); n != "" {
		t.Fatalf("renamed by a wrong code: %q", n)
	}
	if got := r.say("NAME  Mary-Jane O'Neil. " + r.totp()); got != `Done. My name is now "Mary-Jane O'Neil".` {
		t.Fatalf("rename: %q", got)
	}
	if !r.ch.SessionUnlocked(r.clock()) {
		t.Fatal("a code-generator code did not unlock the session")
	}
}

// TestNameInUnlockedSessionNeedsTheTextedConfirmation: an unlocked session
// does not prove who sent NAME, so the broker texts a fixed-wording
// confirmation with a one-time code to the owner's number and renames only
// on NAME <that code>.
func TestNameInUnlockedSessionNeedsTheTextedConfirmation(t *testing.T) {
	r := named(t)
	r.unlock()
	got := r.say("NAME Dave Smith")
	m := nameCodeRe.FindStringSubmatch(got)
	if m == nil || !strings.HasPrefix(got, `Change my name to "Dave Smith"? `) {
		t.Fatalf("confirmation: %q", got)
	}
	if n := r.ch.Name(); n != "" {
		t.Fatalf("renamed before confirmation: %q", n)
	}
	if got := r.say("NAME " + m[1]); got != `Done. My name is now "Dave Smith".` {
		t.Fatalf("confirm: %q", got)
	}
	// The code is spent.
	if got := r.say("NAME " + m[1]); got != "No rename is waiting. Send NAME and the new name." {
		t.Fatalf("reused code: %q", got)
	}
	got = r.say("NAME Ann Lee")
	if m = nameCodeRe.FindStringSubmatch(got); m == nil || !strings.HasPrefix(got, `Change my name from "Dave Smith" to "Ann Lee"? `) {
		t.Fatalf("second confirmation: %q", got)
	}
	if got := r.agent.got(); len(got) != 0 {
		t.Fatalf("agent got %q", got)
	}
}

// TestSpoofedNameRenamesNothing (A14): a spoofer on the owner's number
// never sees the replies, so a NAME it sends in an unlocked session waits
// on a code it cannot read; guesses count and void it after three. In a
// locked session it is held and renames nothing, and RUN does not run it.
func TestSpoofedNameRenamesNothing(t *testing.T) {
	r := named(t)
	r.unlock()
	r.say("NAME Evil Twin") // the confirmation goes to the owner's phone
	for i := 0; i < WrongPerRequest-1; i++ {
		if got := r.say("NAME 000000"); !strings.HasPrefix(got, "Wrong code. Nothing changed.") {
			t.Fatalf("guess %d: %q", i, got)
		}
	}
	if got := r.say("NAME 000000"); !strings.HasPrefix(got, "Wrong code 3 times; it is void. Nothing changed.") {
		t.Fatalf("third guess: %q", got)
	}
	if n := r.ch.Name(); n != "" {
		t.Fatalf("spoofed rename: %q", n)
	}

	// Locked: held, not renamed; RUN and code guesses do nothing.
	r2 := named(t)
	if got := r2.say("NAME Evil Twin"); !strings.HasPrefix(got, "Locked. Your message is held for 15 min.") {
		t.Fatalf("locked: %q", got)
	}
	if got := r2.say("RUN"); got != "Nothing is held." {
		t.Fatalf("RUN: %q", got)
	}
	if got := r2.say("NAME 123456"); got != "No rename is waiting. Send NAME and the new name." {
		t.Fatalf("guess while locked: %q", got)
	}
	if n := r2.ch.Name(); n != "" {
		t.Fatalf("locked rename: %q", n)
	}
	if got := r2.agent.got(); len(got) != 0 {
		t.Fatalf("agent got %q", got)
	}
}

// TestHeldNameAsksForConfirmationAfterUnlock: NAME in a locked session is
// held for the unlock (CH-14); a code-only unlock does not run it but
// turns it into the fixed-wording confirmation, since the code proves the
// owner, not who wrote the held text.
func TestHeldNameAsksForConfirmationAfterUnlock(t *testing.T) {
	r := named(t)
	r.say("NAME Dave Smith")
	got := r.say(r.totp())
	m := nameCodeRe.FindStringSubmatch(got)
	if m == nil || !strings.HasPrefix(got, "Unlocked until ") || !strings.Contains(got, `Change my name to "Dave Smith"? `) {
		t.Fatalf("unlock: %q", got)
	}
	if got := r.say("RUN"); got != "Nothing is held." {
		t.Fatalf("RUN: %q", got)
	}
	if n := r.ch.Name(); n != "" {
		t.Fatalf("renamed before confirmation: %q", n)
	}
	if got := r.say("NAME " + m[1]); got != `Done. My name is now "Dave Smith".` {
		t.Fatalf("confirm: %q", got)
	}
}

// TestNameConfirmationAfterTheSessionLockedNeedsAStrongCode: a texted code
// never renames outside an unlocked session (CH-11).
func TestNameConfirmationAfterTheSessionLockedNeedsAStrongCode(t *testing.T) {
	r := named(t)
	r.unlock()
	m := nameCodeRe.FindStringSubmatch(r.say("NAME Dave Smith"))
	if err := r.ch.RequireUnlock(); err != nil {
		t.Fatal(err)
	}
	if got := r.say("NAME " + m[1]); !strings.HasPrefix(got, "Wrong code. Nothing changed.") {
		t.Fatalf("texted code while locked: %q", got)
	}
	if n := r.ch.Name(); n != "" {
		t.Fatalf("renamed: %q", n)
	}
	if got := r.say("NAME " + r.totp()); got != `Done. My name is now "Dave Smith".` {
		t.Fatalf("strong code: %q", got)
	}
}

// TestNameCodeInChallengeModeIsDropped: in challenge mode a NAME with a
// code of any accepted length (6 to 8 digits) is dropped like any other
// code outside the challenge: ignored, not counted (CH-11, A14).
func TestNameCodeInChallengeModeIsDropped(t *testing.T) {
	r := named(t)
	r.unlock()
	if m := nameCodeRe.FindStringSubmatch(r.say("NAME Dave Smith")); m == nil {
		t.Fatal("no pending rename")
	}
	r.ch.codes.st.Challenged = true
	wrong := len(r.ch.codes.st.Wrong)
	for _, in := range []string{"NAME 123456", "NAME 1234567", "NAME 12345678"} {
		if got := r.say(in); strings.HasPrefix(got, "Wrong code") {
			t.Errorf("%s: checked: %q", in, got)
		}
		if n := len(r.ch.codes.st.Wrong); n != wrong {
			t.Errorf("%s: wrong count %d, want %d", in, n, wrong)
		}
	}
	if n := r.ch.Name(); n != "" {
		t.Fatalf("renamed: %q", n)
	}
}

// TestNameCheckRefusesBeforeAnyCode: a name failing CH-21's check is
// refused in fixed wording, locked or not, and nothing is held.
func TestNameCheckRefusesBeforeAnyCode(t *testing.T) {
	r := named(t)
	for in, why := range map[string]string{
		"NAME Stop":           "that is one of my control words",
		"NAME Agent OS":       `a name cannot contain "AgentOS" or "assistant"`,
		"NAME Dave Assistant": `a name cannot contain "AgentOS" or "assistant"`,
		"NAME mark jones":     "that is your own name",
	} {
		if got := r.say(in); got != "I can't take that name: "+why+". Nothing changed." {
			t.Errorf("%s: %q", in, got)
		}
	}
	if got := r.say(r.totp()); got != "Unlocked until Oct 11 12:00." {
		t.Fatalf("something was held: %q", got)
	}
}

// TestChatStartingWithNameStillReachesTheAgent: NAME counts only with a
// name that fits the character rule as its argument (CH-11's whole-message
// rule); other messages starting with "name" are task chat.
func TestChatStartingWithNameStillReachesTheAgent(t *testing.T) {
	r := named(t)
	r.unlock()
	r.say("name the file report.pdf")
	r.say("Name a good restaurant near me with 4 stars")
	if got := r.agent.got(); len(got) != 2 || got[0] != "name the file report.pdf" {
		t.Fatalf("agent got %q", got)
	}
}

// TestNameWorksWithModelsDown: NAME is a control word, answered by the
// broker with every model and guest down (CH-2).
func TestNameWorksWithModelsDown(t *testing.T) {
	r := named(t)
	r.down = true
	r.ch = r.open()
	if got := r.say("NAME Dave Smith " + r.totp()); got != `Done. My name is now "Dave Smith".` {
		t.Fatalf("rename: %q", got)
	}
	if got := r.say("NAME"); got != `My name is "Dave Smith".` {
		t.Fatalf("name: %q", got)
	}
}
