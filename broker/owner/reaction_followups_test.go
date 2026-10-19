package owner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/modem"
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

// A phone cuts a long quote, so a nest may end without its closing quotes
// (`Pinned “Liked “<request cut>…`). It still quotes a live request: a
// reaction, never chat with a live code (review of #2385).
func TestACutNestOnALiveRequestIsAReaction(t *testing.T) {
	for _, restart := range []bool{false, true} {
		r := newRig(t, nil)
		r.unlock()
		if _, err := r.ch.Request([]Item{lowItem("i1")}, 0); err != nil {
			t.Fatal(err)
		}
		req := r.inbox()
		code := lowCodeRe.FindStringSubmatch(req)[2]
		if restart {
			r.ch = r.open()
		}
		before := len(r.agent.got())
		forms := []string{
			"Pinned “Liked “" + req[:len(req)/2] + "…",
			"Pinned “Liked “" + req[:len(req)/2],
			"Pinned “Liked “" + req + "”",
			"Pinned “Liked “" + req,
			"Cancel “Loved “Pinned “" + req[:len(req)/2] + "…",
		}
		for _, f := range forms {
			if got := r.say(f); !strings.Contains(got, "reaction") {
				t.Fatalf("restart=%v %q replied %q, want it read as a reaction", restart, f, got)
			}
		}
		got := r.agent.got()[before:]
		if len(got) != len(forms) {
			t.Fatalf("restart=%v agent got %q, want %d reaction events", restart, got, len(forms))
		}
		for _, g := range got {
			if strings.Contains(g, code) || strings.Contains(g, "YES") || !strings.HasPrefix(g, "Owner reaction:") {
				t.Fatalf("restart=%v agent got %q, want an event with no request or code", restart, g)
			}
		}
	}
}

// CH-11: a cut nest round only the agent's own text is still chat.
func TestACutNestOnAnAgentTextIsStillChat(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	before := len(r.agent.got())
	r.say("Pinned “Liked “Agent: " + forgottenReply[:40] + "…")
	got := r.agent.got()[before:]
	if len(got) != 1 || !strings.Contains(got[0], "Pinned") {
		t.Fatalf("agent got %q, want the owner's words as chat", got)
	}
}

// After a restart a quote cut inside the code (1 to 3 digits, or part of a
// challenge token) still marks the guarded text.
func TestAQuoteCutInsideACodeIsAReactionAfterARestart(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	const signIn = "Your sign-in code is 482913, good for ten minutes."
	const unlock = "Reply UNLOCK K7M2 to unlock the box for ten minutes."
	for _, s := range []string{signIn, unlock} {
		if err := r.ch.sendTemplate(s); err != nil {
			t.Fatal(err)
		}
		r.inbox()
	}
	r.ch = r.open()
	before := len(r.agent.got())
	quotes := []string{
		"Liked “Your sign-in code is 4…",
		"Liked “Your sign-in code is 48…",
		"Liked “Your sign-in code is 482",
		"Pinned “Your sign-in code is 482…”",
		"Pinned “Liked “Your sign-in code is 482…",
		"Liked “Reply UNLOCK K7M…",
		"Liked “Reply UNLOCK K…",
		"Liked “Reply UNLOCK K7M2 to unlock",
	}
	for _, q := range quotes {
		if got := r.say(q); !strings.Contains(got, "reaction") {
			t.Fatalf("%q replied %q, want it read as a reaction", q, got)
		}
	}
	got := r.agent.got()[before:]
	if len(got) != len(quotes) {
		t.Fatalf("agent got %q, want %d reaction events", got, len(quotes))
	}
	for _, g := range got {
		if strings.Contains(g, "482") || strings.Contains(g, "K7M") || strings.Contains(g, "sign-in") {
			t.Fatalf("agent got %q, want an event with no code or text", g)
		}
	}
}

// The saved guard never holds a challenge token, whatever its case, and the
// token in a quote still matches it after a restart.
func TestTheSavedGuardHoldsNoChallengeToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	r := newRig(t, FileStore{Path: path})
	r.unlock()
	if err := r.ch.sendTemplate("Reply UNLOCK K7M2 to unlock the box for ten minutes."); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(b)), "k7m2") {
		t.Fatalf("the store holds a challenge token: %s", b)
	}
	if !strings.Contains(string(b), "guarded") {
		t.Fatalf("the store holds no guarded entry: %s", b)
	}
	r.ch = r.open()
	before := len(r.agent.got())
	if got := r.say("Pinned “Reply UNLOCK K7M2 to unlock the box for ten minutes.”"); !strings.Contains(got, readAsReaction) {
		t.Fatalf("after a restart owner got %q, want %q", got, readAsReaction)
	}
	for _, g := range r.agent.got()[before:] {
		if strings.Contains(strings.ToLower(g), "k7m2") {
			t.Fatalf("agent got %q", g)
		}
	}
}

// A nest four forms deep round a cut request is still peeled to it.
func TestADeepNestRoundACutRequestIsAReaction(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if _, err := r.ch.Request([]Item{lowItem("i1")}, 0); err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	cut := req[:len(req)/2] + "…"
	before := len(r.agent.got())
	if got := r.say("Pinned “Liked “Loved “Cancel “" + cut + "””””"); !strings.Contains(got, "reaction") {
		t.Fatalf("replied %q, want it read as a reaction", got)
	}
	if g := r.agent.got()[before:]; len(g) != 1 || !strings.HasPrefix(g[0], "Owner reaction:") {
		t.Fatalf("agent got %q, want one reaction event", g)
	}
}

func (r *rig) guardedMarks() []GuardedMark {
	r.ch.mu.Lock()
	defer r.ch.mu.Unlock()
	return append([]GuardedMark(nil), r.ch.codes.st.Guarded...)
}

// The saved guard drops an entry past 24 hours when the next is saved, and
// keeps one exactly 24 hours old.
func TestTheSavedGuardPrunesPast24Hours(t *testing.T) {
	r := newRig(t, nil)
	r.ch.remember(sentText{text: "Sign-in code 111111 for site A.", at: r.clock()})
	r.advance(24 * time.Hour)
	r.ch.remember(sentText{text: "Sign-in code 222222 for site B.", at: r.clock()})
	if got := r.guardedMarks(); len(got) != 2 {
		t.Fatalf("saved %+v, want an entry exactly 24 hours old kept", got)
	}
	r.advance(time.Second)
	r.ch.remember(sentText{text: "Sign-in code 333333 for site C.", at: r.clock()})
	got := r.guardedMarks()
	if len(got) != 2 || !strings.Contains(got[0].Text, "site b") || !strings.Contains(got[1].Text, "site c") {
		t.Fatalf("saved %+v, want the entry past 24 hours dropped", got)
	}
}

// The saved guard holds at most the 20 latest guarded texts.
func TestTheSavedGuardHoldsTheLatest20(t *testing.T) {
	r := newRig(t, nil)
	for i := 0; i < recentTexts+1; i++ {
		r.ch.remember(sentText{text: "Sign-in code 111111 for site " + string(rune('a'+i)) + ".", at: r.clock()})
	}
	got := r.guardedMarks()
	if len(got) != recentTexts || !strings.Contains(got[0].Text, "site b") || !strings.Contains(got[len(got)-1].Text, "site u") {
		t.Fatalf("saved %d entries %+v, want the latest %d", len(got), got, recentTexts)
	}
}

// A restart brings back only the saved entries inside 24 hours.
func TestARestartRestoresOnlyTheEntriesInsideTheAge(t *testing.T) {
	for _, tc := range []struct {
		age  time.Duration
		want int
	}{{24 * time.Hour, 1}, {24*time.Hour + time.Second, 0}} {
		r := newRig(t, nil)
		r.ch.remember(sentText{text: "Sign-in code 111111 for site A.", at: r.clock()})
		r.advance(tc.age)
		r.ch = r.open()
		r.ch.recent.mu.Lock()
		n := len(r.ch.recent.texts)
		r.ch.recent.mu.Unlock()
		if n != tc.want {
			t.Fatalf("after %v the window holds %d texts, want %d", tc.age, n, tc.want)
		}
	}
}

// slowLine holds a send until release is closed.
type slowLine struct {
	modem.Modem
	in      chan struct{}
	release chan struct{}
	once    sync.Once
}

func (l *slowLine) Send(to, text string) error {
	l.once.Do(func() { close(l.in) })
	<-l.release
	return l.Modem.Send(to, text)
}

// A release in flight finishes before a forget returns, so no held agent
// text goes out after the deletion (#2374, lock order pmu).
func TestAForgetWaitsForAReleaseInFlight(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	sl := &slowLine{in: make(chan struct{}), release: make(chan struct{})}
	prev := r.edit
	r.edit = func(c *Config) { prev(c); sl.Modem = c.Modem; c.Modem = sl }
	r.ch = r.open()
	if err := r.ch.Notify(forgottenReply); err != nil {
		t.Fatal(err)
	}
	r.advance(8 * time.Hour)
	released := make(chan error, 1)
	go func() { released <- r.ch.Release() }()
	select {
	case <-sl.in:
	case <-time.After(5 * time.Second):
		t.Fatal("the release never reached the modem")
	}
	forgot := make(chan struct{})
	go func() { r.ch.ForgetRecent(); close(forgot) }()
	select {
	case <-forgot:
		t.Fatal("a forget returned while a release was in flight")
	case <-time.After(200 * time.Millisecond):
	}
	close(sl.release)
	if err := <-released; err != nil {
		t.Fatal(err)
	}
	select {
	case <-forgot:
	case <-time.After(5 * time.Second):
		t.Fatal("the forget never returned")
	}
}

// After a restart a quote cut inside a code at one end only is still a
// reaction: the other end may hold digits that are no code (a time, the
// request's ID), or the text may start with a digit, so the head and the
// tail are masked alone as well as together.
func TestAQuoteCutInsideACodeAtOneEndIsAReactionAfterARestart(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if _, err := r.ch.Request([]Item{lowItem("i1")}, 0); err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	m := lowCodeRe.FindStringSubmatch(req)
	id, code := m[1], m[2]
	expires := regexp.MustCompile(`Expires ([0-9]{1,2}:[0-9]{2})\.`).FindStringSubmatch(req)
	if expires == nil {
		t.Fatalf("request %q names no expiry time", req)
	}
	const bank = "2 factor code for your bank is 482913."
	if err := r.ch.sendTemplate(bank); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.advance(time.Minute)
	r.ch = r.open()
	before := len(r.agent.got())
	quotes := []string{
		"Liked “" + code[3:] + " or NO " + id,
		"Pinned “Liked “" + code[3:] + " or NO " + id,
		"Liked “ " + expires[1] + ". Reply YES " + id + " " + code[:3] + "…",
		"Liked “2 factor code for your bank is 48…",
	}
	for _, q := range quotes {
		if got := r.say(q); !strings.Contains(got, "reaction") {
			t.Fatalf("after a restart %q replied %q, want it read as a reaction", q, got)
		}
	}
	got := r.agent.got()[before:]
	if len(got) != len(quotes) {
		t.Fatalf("agent got %q, want %d reaction events", got, len(quotes))
	}
	for _, g := range got {
		if strings.Contains(g, code[:3]) || strings.Contains(g, code[3:]) || strings.Contains(g, "48") || strings.Contains(g, "YES") {
			t.Fatalf("agent got %q, want an event with no code digits or text", g)
		}
	}
}

// A quote cut at its start with an ellipsis is matched without it, live
// and after a restart, so a live code in it never reaches the agent as
// chat.
func TestAQuoteWithALeadingEllipsisIsAReaction(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if _, err := r.ch.Request([]Item{lowItem("i1")}, 0); err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	m := lowCodeRe.FindStringSubmatch(req)
	id, code := m[1], m[2]
	quotes := []string{
		"Liked “… YES " + id + " " + code + "…",
		"Liked “...YES " + id + " " + code + " or NO " + id + ".”",
	}
	check := func(when string) {
		before := len(r.agent.got())
		for _, q := range quotes {
			if got := r.say(q); !strings.Contains(got, "reaction") {
				t.Fatalf("%s %q replied %q, want it read as a reaction", when, q, got)
			}
		}
		got := r.agent.got()[before:]
		if len(got) != len(quotes) {
			t.Fatalf("%s agent got %q, want %d reaction events", when, got, len(quotes))
		}
		for _, g := range got {
			if strings.Contains(g, code) || strings.Contains(g, "YES") {
				t.Fatalf("%s agent got %q, want an event with no code", when, g)
			}
		}
	}
	check("live")
	r.advance(time.Minute)
	r.ch = r.open()
	check("after a restart")
}

// REQ: CH11-G1, CH11-G2, CH11-G3, CH11-G4

// Four reaction-quote gaps from the O45 Security review (#2392): a short
// cut, a doubled ellipsis, a cut inside a code at both ends, and a request
// pushed out of the window by later box texts.

// lowRequest sends a one-item request and returns its ID and code.
func lowRequest(r *rig) (id, code string) {
	r.t.Helper()
	if _, err := r.ch.Request([]Item{lowItem("i1")}, 0); err != nil {
		r.t.Fatal(err)
	}
	m := lowCodeRe.FindStringSubmatch(r.inbox())
	return m[1], m[2]
}

// reactionsHide says each quote and checks it was read as a reaction whose
// event holds none of the hidden strings.
func reactionsHide(r *rig, when string, quotes []string, hidden ...string) {
	r.t.Helper()
	before := len(r.agent.got())
	for _, q := range quotes {
		if got := r.say(q); !strings.Contains(got, "reaction") {
			r.t.Fatalf("%s %q replied %q, want it read as a reaction", when, q, got)
		}
	}
	got := r.agent.got()[before:]
	if len(got) != len(quotes) {
		r.t.Fatalf("%s agent got %q, want %d reaction events", when, got, len(quotes))
	}
	for _, g := range got {
		for _, h := range hidden {
			if strings.Contains(g, h) {
				r.t.Fatalf("%s agent got %q, want an event without %q", when, g, h)
			}
		}
	}
}

// CH11-G1: a quote shorter than minQuote that is a cut of a guarded text
// is a reaction, live and after a restart; a short cut of the agent's own
// text stays chat.
func TestShortCutQuoteOfARequestIsAReaction(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	id, code := lowRequest(r)
	quotes := []string{
		"Liked “YES " + id + " " + code[:2],
		"Liked “...YES " + id + " " + code[:2],
		"Liked “" + code[4:] + " or NO",
	}
	for _, q := range quotes[:2] {
		if n := utf8.RuneCountInString(normQuote(strings.TrimPrefix(q, "Liked “"))); n >= minQuote {
			t.Fatalf("quote %q is %d runes, want it under minQuote", q, n)
		}
	}
	reactionsHide(r, "live", quotes, code[:2], code[4:], "YES")
	if err := r.ch.Converse("Your table is booked for 4829 guests"); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	before := len(r.agent.got())
	r.say("Liked “Agent: Your t")
	if got := r.agent.got()[before:]; len(got) != 1 || !strings.Contains(got[0], "Liked") {
		t.Fatalf("agent got %q, want a short cut of its own text as chat", got)
	}
	r.advance(time.Minute)
	r.ch = r.open()
	reactionsHide(r, "after a restart", quotes, code[:2], code[4:], "YES")
}

// CH11-G2: repeated ellipses at either end are all dropped, so a quote cut
// with two of them still marks the request.
func TestDoubledEllipsisQuoteIsAReaction(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	id, code := lowRequest(r)
	quotes := []string{
		"Liked “… …" + code[3:] + " or NO " + id + "… …",
		"Liked “......YES " + id + " " + code[:3] + "……",
	}
	if got := normQuote("… ... …x… ..."); got != "x" {
		t.Fatalf("normQuote kept ellipses: %q", got)
	}
	reactionsHide(r, "live", quotes, code[:3], code[3:], "YES")
	r.advance(time.Minute)
	r.ch = r.open()
	reactionsHide(r, "after a restart", quotes, code[:3], code[3:], "YES")
}

// CH11-G3: a quote cut inside a code at each end (a request that holds its
// code twice) matches the saved text only with both cuts masked.
func TestQuoteCutAtBothEndsIsAReactionAfterARestart(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if _, err := r.ch.Request([]Item{lowItem("i1"), lowItem("i2")}, 0); err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	m := regexp.MustCompile(`YES ([A-Z][0-9]{1,2}) ([0-9]{6}) for all, YES [A-Z][0-9]{1,2} 1 2 ([0-9]{6})`).FindStringSubmatch(req)
	if m == nil {
		t.Fatalf("request %q does not hold its code twice", req)
	}
	id, code := m[1], m[2]
	q := "Liked “" + code[3:] + " for all, YES " + id + " 1 2 " + code[:3]
	n := maskCodes(normQuote(strings.TrimPrefix(q, "Liked “")))
	head := cutCodeHead.ReplaceAllString(n, "#")
	tail := cutCodeTail.ReplaceAllString(n, "#")
	saved := r.guardedMarks()
	for _, one := range []string{head, tail} {
		for _, g := range saved {
			if strings.Contains(g.Text, one) {
				t.Fatalf("one-end form %q matches %q, want only the both-ends form to", one, g.Text)
			}
		}
	}
	r.advance(time.Minute)
	r.ch = r.open()
	reactionsHide(r, "after a restart", []string{q}, code[:3], code[3:], "YES")
}

// CH11-G4: guarded texts live apart from the 20-text cap, so later box
// texts never push a live request out of the window.
func TestLiveRequestSurvivesTwentyFiveMoreBoxTexts(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	id, code := lowRequest(r)
	for i := 0; i < 25; i++ {
		if err := r.ch.sendTemplate("Box note " + strings.Repeat("x", i+1) + "."); err != nil {
			t.Fatal(err)
		}
		r.inbox()
	}
	reactionsHide(r, "live", []string{"Liked “…" + code + " or NO " + id}, code, "YES")
}

// CH11-G4: the guarded texts are bounded: past the cap, a closed request
// leaves the window, while an open one stays until it ages out.
func TestGuardedTextsAreBoundedByAgeAndOpenRequests(t *testing.T) {
	var w recentWindow
	now := time.Unix(1e9, 0)
	open := map[string]bool{"A1": true}
	isOpen := func(id string) bool { return open[id] }
	w.put(sentText{text: "A1: send? Reply YES A1 482913 or NO A1.", at: now, request: true, ids: []string{"A1"}}, isOpen)
	w.put(sentText{text: "B1: send? Reply YES B1 739104 or NO B1.", at: now, request: true, ids: []string{"B1"}}, isOpen)
	for i := 0; i < recentTexts; i++ {
		w.put(sentText{text: "Your code is 5" + strings.Repeat("1", 4+i) + ".", at: now}, isOpen)
		w.add(sentText{text: "Box note " + strings.Repeat("x", i+1) + ".", at: now})
	}
	if _, ok := w.match("reply yes a1 482913 or no a1.", now); !ok {
		t.Fatal("an open request left the window under the cap")
	}
	if _, ok := w.match("reply yes b1 739104 or no b1.", now); ok {
		t.Fatal("a closed request past the guarded cap is still in the window")
	}
	guarded, plain := 0, 0
	for _, s := range w.texts {
		if s.guarded() {
			guarded++
		} else {
			plain++
		}
	}
	if guarded != recentTexts+1 || plain != recentTexts {
		t.Fatalf("window holds %d guarded and %d other texts, want %d and %d", guarded, plain, recentTexts+1, recentTexts)
	}
	later := now.Add(recentMaxAge + time.Minute)
	w.add(sentText{text: "Box note late.", at: later})
	if _, ok := w.match("reply yes a1 482913 or no a1.", later); ok || len(w.texts) != 1 {
		t.Fatalf("window holds %d texts past the age, want only the new one", len(w.texts))
	}
}
