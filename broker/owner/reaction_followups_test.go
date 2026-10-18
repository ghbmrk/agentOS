package owner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// REQ: CAP-3, CH-3, CH-11, CH-15

// Follow-ups to the forget fix (#2360): agent texts held by pacing (#2374),
// nested reaction forms (#2376) and the window after a restart (#2381).

// An agent text held by pacing is dropped by a forget: it may quote a
// forgotten reply, and a release after the deletion would send it and put
// it back in the reaction window (#2374).
func TestAForgetDropsHeldAgentTexts(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	if err := r.ch.Notify(forgottenReply); err != nil {
		t.Fatal(err)
	}
	if got := r.held(); len(got) != 1 || !got[0].Agent {
		t.Fatalf("held %+v, want one agent text", got)
	}
	r.ch.ForgetRecent()
	if got := r.held(); len(got) != 0 {
		t.Fatalf("a forget left held texts %+v", got)
	}
	r.advance(8 * time.Hour)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("a release after a forget sent %q", got)
	}
	if _, ok := r.ch.recent.match(forgottenWords, r.clock()); ok {
		t.Fatal("the forgotten reply is back in the reaction window")
	}
}

// The deletion holds across a restart: the hold is saved without the text.
func TestAForgottenHeldAgentTextDoesNotComeBackAfterARestart(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	if err := r.ch.Notify(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.ch.ForgetRecent()
	r.ch = r.open()
	r.advance(8 * time.Hour)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("a release after a forget and a restart sent %q", got)
	}
}

// A forget drops only the agent's texts: a box text held beside them is
// still sent, and a text held after the forget is held and sent as usual.
func TestAForgetKeepsHeldBoxTextsAndLaterAgentTexts(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	if err := r.ch.Notify(forgottenReply); err != nil {
		t.Fatal(err)
	}
	if err := r.ch.Inform("Backup finished."); err != nil {
		t.Fatal(err)
	}
	r.ch.ForgetRecent()
	if err := r.ch.Notify("A new agent text after the forget."); err != nil {
		t.Fatal(err)
	}
	if got := r.held(); len(got) != 2 {
		t.Fatalf("held %+v, want the box text and the new agent text", got)
	}
	r.advance(8 * time.Hour)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	sent := strings.Join(r.sentTexts(), "\n")
	if strings.Contains(sent, "Acme") || !strings.Contains(sent, "Backup finished.") || !strings.Contains(sent, "A new agent text") {
		t.Fatalf("release sent %q, want the box text and the new agent text only", sent)
	}
}

// A request is live in the window; a nested unlisted form quoting it is a
// reaction whose event shows neither the request nor its code (#2376).
func TestANestedUnlistedFormOnALiveRequestIsAReaction(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if _, err := r.ch.Request([]Item{lowItem("i1")}, 0); err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	code := lowCodeRe.FindStringSubmatch(req)[2]
	before := len(r.agent.got())
	forms := []string{
		"Pinned “Liked “" + req + "””",
		"Pinned “Liked “" + req[:len(req)/2] + "…””",
		"Cancel “Loved “Pinned “" + req + "”””",
		"Pinned “Look at this: " + req + "”",
		"Liked “Loved “" + req + "””",
	}
	for _, f := range forms {
		if got := r.say(f); !strings.Contains(got, "reaction") {
			t.Fatalf("%q replied %q, want it read as a reaction", f, got)
		}
	}
	got := r.agent.got()[before:]
	if len(got) != len(forms) {
		t.Fatalf("agent got %q, want %d reaction events", got, len(forms))
	}
	for _, g := range got {
		if strings.Contains(g, code) || strings.Contains(g, "YES") || !strings.HasPrefix(g, "Owner reaction:") {
			t.Fatalf("agent got %q, want an event that shows neither the request nor its code", g)
		}
	}
}

// CH-11 still holds: a nested form quoting only the agent's own text is chat.
func TestANestedFormOnAnAgentTextIsStillChat(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	before := len(r.agent.got())
	r.say("Pinned “Liked “Agent: " + forgottenReply + "””")
	got := r.agent.got()[before:]
	if len(got) != 1 || !strings.Contains(got[0], "Pinned") {
		t.Fatalf("agent got %q, want the owner's words as chat", got)
	}
}

// After a deletion a nested unlisted form quoting a forgotten agent reply
// is read as a reaction that matched none, not sent as chat.
func TestANestedFormOnAForgottenReplyIsNotChat(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.ch.ForgetRecent()
	before := len(r.agent.got())
	if got := r.say("Pinned “Liked “Agent: " + forgottenReply + "””"); got != readAsReaction {
		t.Fatalf("owner got %q, want %q", got, readAsReaction)
	}
	noForgottenText(t, r.agent.got()[before:])
}

// After a restart a request still open is guarded: the quote of it, in
// each unlisted form, is a reaction and the agent never sees its code
// (#2381).
func TestAnUnlistedFormOnARequestIsAReactionAfterARestart(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if _, err := r.ch.Request([]Item{lowItem("i1")}, 0); err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	code := lowCodeRe.FindStringSubmatch(req)[2]
	r.advance(time.Minute)
	r.ch = r.open()
	before := len(r.agent.got())
	forms := []string{
		"Pinned “" + req + "”",
		"Cancel “" + req + "”",
		"👍 “" + req + "”",
		"Reacted with a heart to “" + req + "”",
		"Pinned “Liked “" + req + "””",
		"Liked “" + req + "”",
	}
	for _, f := range forms {
		if got := r.say(f); !strings.Contains(got, "reaction") {
			t.Fatalf("after a restart %q replied %q, want it read as a reaction", f, got)
		}
	}
	got := r.agent.got()[before:]
	if len(got) != len(forms) {
		t.Fatalf("agent got %q, want %d reaction events", got, len(forms))
	}
	for _, g := range got {
		if strings.Contains(g, code) || strings.Contains(g, "YES") || strings.Contains(g, "Reply") {
			t.Fatalf("agent got %q, want an event that shows neither the request nor its code", g)
		}
	}
}

// A box text that carried a code before the restart is still guarded, and
// its event does not show it.
func TestAnUnlistedFormOnACodeTextIsAReactionAfterARestart(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	const signIn = "Your sign-in code is 482913, good for ten minutes."
	if err := r.ch.sendTemplate(signIn); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.ch = r.open()
	before := len(r.agent.got())
	if got := r.say("Pinned “" + signIn + "”"); !strings.Contains(got, readAsReaction) {
		t.Fatalf("after a restart owner got %q, want %q", got, readAsReaction)
	}
	r.say("Liked “Your sign-in code is 482913, good…”")
	for _, g := range r.agent.got()[before:] {
		if strings.Contains(g, "482913") || strings.Contains(g, "sign-in") {
			t.Fatalf("agent got %q, want an event with no code or text", g)
		}
	}
}

// CH-11 after a restart: a form quoting only an agent reply is chat.
func TestAnUnlistedFormOnAnAgentReplyIsChatAfterARestart(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.ch = r.open()
	before := len(r.agent.got())
	r.say("Pinned “Agent: " + forgottenReply + "”")
	got := r.agent.got()[before:]
	if len(got) != 1 || !strings.Contains(got[0], "Pinned") {
		t.Fatalf("agent got %q, want the owner's words as chat", got)
	}
}

// What is saved holds no code, and an entry past 24 hours is dropped.
func TestTheSavedGuardHoldsNoCodeAndAgesOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	r := newRig(t, FileStore{Path: path})
	r.unlock()
	if _, err := r.ch.Request([]Item{lowItem("i1")}, 0); err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	code := lowCodeRe.FindStringSubmatch(req)[2]
	if err := r.ch.sendTemplate("Your sign-in code is 482913."); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), code) || strings.Contains(string(b), "482913") {
		t.Fatalf("the store holds a code: %s", b)
	}
	if !strings.Contains(string(b), "guarded") {
		t.Fatalf("the store holds no guarded entry: %s", b)
	}
	r.advance(25 * time.Hour)
	r.ch = r.open()
	if _, ok := r.ch.recent.matchGuarded("Your sign-in code is 482913.", r.clock()); ok {
		t.Fatal("an entry past 24 hours still guards")
	}
}
