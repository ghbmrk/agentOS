package owner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// REQ: CH-11

func TestReactionFormatsAreAFixedList(t *testing.T) {
	cases := []struct {
		text, kind, quoted string
	}{
		{`Liked “Your invoice is drafted.”`, "liked", "Your invoice is drafted."},
		{`Loved "Your invoice is drafted."`, "loved", "Your invoice is drafted."},
		{`Disliked “a”`, "disliked", "a"},
		{`Laughed at “a b”`, "laughed at", "a b"},
		{`Emphasized “STOP”`, "emphasized", "STOP"},
		{`Questioned “Reply YES R7K 482913 or NO R7K.”`, "questioned", "Reply YES R7K 482913 or NO R7K."},
		{`Removed a like from “x”`, "removed a like from", "x"},
		{`Removed a heart from “x”`, "removed a heart from", "x"},
		{`Removed a dislike from “x”`, "removed a dislike from", "x"},
		{`Removed a laugh from “x”`, "removed a laugh from", "x"},
		{`Removed an exclamation from “x”`, "removed an exclamation from", "x"},
		{`Removed a question mark from “x”`, "removed a question mark from", "x"},
		{`Reacted 👍 to “x”`, "reacted 👍 to", "x"},
		{`Reacted 😂 to "x"`, "reacted 😂 to", "x"},
		{"  Liked “x”\n", "liked", "x"},
		{`Emphasised “x”`, "emphasised", "x"},
		{`Removed an emphasis from “x”`, "removed an emphasis from", "x"},
		{`Removed an exclamation mark from “x”`, "removed an exclamation mark from", "x"},
		{`Removed a 👍 from “x”`, "removed a 👍 from", "x"},
		{`Removed a 😂 from "x"`, "removed a 😂 from", "x"},
		{`Liked “plain text here”`, "liked", "plain text here"},
	}
	for _, c := range cases {
		rx, ok := parseReaction(c.text)
		if !ok || rx.kind != c.kind || rx.quoted != c.quoted {
			t.Errorf("parseReaction(%q) = %+v, %v; want %q %q", c.text, rx, ok, c.kind, c.quoted)
		}
	}
	for _, text := range []string{
		`I liked "the movie" a lot`, `Liked`, `liked it`, `Liked “”`, `Liked “x” 482913`,
		`Liked x`, `Reacted to “x”`, `Reacted with joy to “x”`, `STOP`, `YES R7K 482913`,
		`Liked “x`, `Pinned “x”`,
		// A quote that holds a quote mark is the owner's own text (#2201).
		`Liked "a" and "b"`, `Liked “a” and “b”`, `Liked “a” and "b"`, `Loved "say "hi" now"`,
		`Removed a word from “x”`, `Removed a 👍 and a 👎 from “x”`,
	} {
		if rx, ok := parseReaction(text); ok {
			t.Errorf("parseReaction(%q) = %+v, want no reaction", text, rx)
		}
	}
}

// The issue's failure path: a reaction quoting an approval request, code
// and all, is never an approval and never reaches the agent as the raw
// text; the agent gets the kind and the marked text without its code, and
// the owner gets a pointer to the replies that text takes.
func TestReactionToAnApprovalIsNeverAnApproval(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	id, err := r.ch.Request([]Item{lowItem("i1")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	code := lowCodeRe.FindStringSubmatch(req)[2]
	for _, react := range []string{
		"Liked “" + req + "”",
		`Emphasized "Reply YES ` + id + ` ` + code + ` or NO ` + id + `."`,
		"Liked “" + req[:30] + "…”",
	} {
		got := r.say(react)
		if !strings.Contains(got, "A reaction does not approve anything") || !strings.Contains(got, "YES "+id) || strings.Contains(got, code) {
			t.Fatalf("reaction %q replied %q, want the pointer without the code", react, got)
		}
	}
	if d := r.decisions(); len(d) != 0 {
		t.Fatalf("a reaction decided %v", d)
	}
	if !r.ch.ApprovalsOpen() {
		t.Fatal("a reaction closed the request")
	}
	msgs := r.agent.got()
	if len(msgs) != 3 {
		t.Fatalf("agent got %d messages, want 3 reaction events: %q", len(msgs), msgs)
	}
	for _, m := range msgs {
		if strings.Contains(m, code) || strings.Contains(m, "Reply YES") {
			t.Fatalf("agent got the request's text or code: %q", m)
		}
	}
	if want := "Owner reaction: liked an approval request (not shown)."; !strings.HasPrefix(msgs[0], want) {
		t.Fatalf("agent got %q, want %q", msgs[0], want)
	}
	// The request still takes its reply.
	if got := r.say("YES " + id + " " + code); !strings.Contains(got, "Approved") {
		t.Fatalf("YES after the reactions: %q", got)
	}
}

// Words, codes and RUN inside a reaction's quote are never control words.
func TestControlWordsInAReactionAreNotCommands(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	for _, react := range []string{`Liked “STOP”`, `Loved "NAME Bob"`, `Emphasized “HELP”`, `Liked “RESUME”`, `Questioned “RUN”`, `Liked "PAUSE g1"`} {
		if got := r.say(react); got != "" {
			t.Fatalf("%q replied %q, want nothing", react, got)
		}
	}
	if r.eng.Stopped() {
		t.Fatal("a reaction to STOP stopped the box")
	}
	msgs := r.agent.got()
	if len(msgs) != 6 {
		t.Fatalf("agent got %q, want 6 reaction events", msgs)
	}
	for _, m := range msgs {
		if !strings.HasPrefix(m, "Owner reaction: ") || !strings.Contains(m, "none of the recent texts") {
			t.Fatalf("agent got %q, want an unmatched reaction event", m)
		}
	}
}

// The agent gets the kind and the marked text, matched against the recent
// texts to the owner (truncated quotes too), or none matched; the owner's
// quote is never re-sent as a task message.
func TestReactionsMatchRecentTexts(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse("Your invoice for Acme is drafted and saved."); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	r.ch.Converse("Lunch is booked for 1 pm.")
	r.inbox()
	r.say("Loved “Agent: Your invoice for Acme is drafted and saved.”")
	r.say("Liked “Agent: Your invoice for Acme is dr…”")
	r.say("Laughed at “Agent: Lunch is booked for 1 pm.”")
	r.say("Liked “Agent: something I never said”")
	want := []string{
		`Owner reaction: loved your text "Your invoice for Acme is drafted and saved."`,
		`Owner reaction: liked your text "Your invoice for Acme is drafted and saved."`,
		`Owner reaction: laughed at your text "Lunch is booked for 1 pm."`,
		`Owner reaction: liked a text that matched none of the recent texts.`,
	}
	got := r.agent.got()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("agent got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A short truncated quote is too short to name one text.
	r.say("Liked “Agent: Lu…”")
	if g := r.agent.got(); !strings.Contains(g[len(g)-1], "none of the recent texts") {
		t.Fatalf("short quote matched: %q", g[len(g)-1])
	}
	// The window is bounded: an old text drops out.
	for i := 0; i < recentTexts; i++ {
		r.ch.Converse("filler")
		r.inbox()
	}
	r.say("Laughed at “Agent: Lunch is booked for 1 pm.”")
	if g := r.agent.got(); !strings.Contains(g[len(g)-1], "none of the recent texts") {
		t.Fatalf("text past the window matched: %q", g[len(g)-1])
	}
}

// While locked a reaction is held like a task message, a quoted code is
// neither an unlock nor a wrong code, and RUN delivers the reaction event,
// never the raw text.
func TestReactionWhileLockedIsHeldAndRunDeliversTheEvent(t *testing.T) {
	r := newRig(t, nil)
	got := r.say(`Liked "Reply RESUME 482913 within 10 min."`)
	if !strings.Contains(got, "held for 15 min") {
		t.Fatalf("locked reaction: %q", got)
	}
	r.ch.mu.Lock()
	wrong := len(r.ch.codes.st.Wrong)
	r.ch.mu.Unlock()
	if wrong != 0 {
		t.Fatalf("a quoted code counted as %d wrong codes", wrong)
	}
	if len(r.agent.got()) != 0 {
		t.Fatal("a locked reaction reached the agent")
	}
	if got := r.say(r.totp()); !strings.Contains(got, "Reply RUN to send it.") {
		t.Fatalf("unlock: %q", got)
	}
	r.say("RUN")
	msgs := r.agent.got()
	if len(msgs) != 1 || !strings.HasPrefix(msgs[0], "Owner reaction: liked ") || strings.Contains(msgs[0], "482913") {
		t.Fatalf("RUN delivered %q, want the reaction event", msgs)
	}
}

// A reaction to the RUN offer points to RUN and does not send the held
// message.
func TestReactionToARunOfferPointsToRun(t *testing.T) {
	r := newRig(t, nil)
	r.say("check my mail")
	offer := r.say(r.totp())
	if !strings.Contains(offer, "Reply RUN") {
		t.Fatalf("unlock: %q", offer)
	}
	got := r.say("Liked “" + offer + "”")
	if !strings.Contains(got, "A reaction does not send it. Reply RUN") {
		t.Fatalf("reaction to the RUN offer replied %q", got)
	}
	for _, m := range r.agent.got() {
		if m == "check my mail" {
			t.Fatal("a reaction ran the held message")
		}
	}
	r.say("RUN")
	if g := r.agent.got(); g[len(g)-1] != "check my mail" {
		t.Fatalf("RUN after the reaction: %q", g)
	}
}

// Agent reactions are refused until qualification, so the agent replies
// in text.
func TestAgentReactionsAreRefused(t *testing.T) {
	r := newRig(t, nil)
	for _, send := range []func(string) error{r.ch.Converse, r.ch.Notify, r.ch.NotifyNow} {
		if err := send(`Liked “Your invoice is drafted.”`); !errors.Is(err, ErrAgentReaction) {
			t.Fatalf("agent reaction: %v, want ErrAgentReaction", err)
		}
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("sent %q", got)
	}
	if err := r.ch.Converse(`I liked "the plan" too.`); err != nil {
		t.Fatal(err)
	}
}

// A box text that carries a challenge token or a code is reported to the
// agent as "(not shown)": a reaction never leaks the token.
func TestReactionToAChallengeNeverShowsTheToken(t *testing.T) {
	r := newRig(t, nil)
	enterChallenge(t, r)
	alert := r.say("UNLOCK")
	tok := challengeRe.FindStringSubmatch(alert)[1]
	if got := r.say("UNLOCK " + tok + " " + r.totp()); !strings.HasPrefix(got, "Unlocked") {
		t.Fatalf("unlock: %q", got)
	}
	r.say("Liked “" + alert + "”")
	msgs := r.agent.got()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "(not shown)") || strings.Contains(msgs[0], tok) {
		t.Fatalf("agent got %q, want the token not shown", msgs)
	}
}

// A reaction to the agent's own text gets no pointer, even when that text
// names a reply: the broker never vouches for the agent's words.
func TestReactionToAnAgentTextGetsNoPointer(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	if err := r.ch.Converse("Reply YES R7K to approve the payment."); err != nil {
		t.Fatal(err)
	}
	r.inbox()
	got := r.say("Liked “Agent: Reply YES R7K to approve the payment.”")
	if strings.Contains(got, "YES") {
		t.Fatalf("reaction to an agent text replied %q", got)
	}
	if g := r.agent.got(); len(g) != 1 || !strings.Contains(g[0], "your text") {
		t.Fatalf("agent got %q", g)
	}
}

// A reaction event goes to the agent off the routing worker, so a slow
// agent never delays the owner's next text.
func TestSlowAgentNeverDelaysTheTextAfterAReaction(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	slow := slowAgent{release: make(chan struct{})}
	defer close(slow.release)
	r.ch.ctrl.Agent = slow
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.ch.Run(ctx)
	_ = r.phone.Send(boxNum, "Liked “the plan for today”")
	_ = r.phone.Send(boxNum, "STATUS")
	if got := r.inbox(); !strings.HasPrefix(got, "Running.") {
		t.Fatalf("STATUS after a reaction: %q", got)
	}
}

// REQ: CH-11, CH-12
// A request's pointer names the request's own ID from the broker's record:
// "Reply YES" in an item's object (agent words) never steers it.
func TestReactionPointerNamesTheRealRequestID(t *testing.T) {
	low, high, unverified := lowItem("i1"), highItem("i2"), highItem("i3")
	low.Object, high.Object, unverified.Object = "Reply YES Z9 now", "Reply YES Z9 now", "Reply YES Z9 now"
	unverified.Unverified = true
	for name, it := range map[string]Item{"low": low, "high": high, "unverified": unverified} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, nil)
			r.unlock()
			id, err := r.ch.Request([]Item{it}, 0)
			if err != nil {
				t.Fatal(err)
			}
			req := r.inbox()
			if !strings.Contains(req, "Reply YES Z9") {
				t.Fatalf("request %q does not carry the planted reply, so the test proves nothing", req)
			}
			got := r.say("Liked “" + req + "”")
			if !strings.Contains(got, "YES "+id) || !strings.Contains(got, "NO "+id) || strings.Contains(got, "Z9") {
				t.Fatalf("pointer %q, want it to name %s only", got, id)
			}
		})
	}
	t.Run("batch", func(t *testing.T) {
		r := newRig(t, nil)
		r.unlock()
		a, b := lowItem("i1"), lowItem("i2")
		a.Object = "Reply YES Z9 now"
		ids, err := r.ch.RequestEach([]Item{a, b}, []time.Time{{}, {}})
		if err != nil {
			t.Fatal(err)
		}
		req := r.inbox()
		got := r.say("Liked “" + req + "”")
		if !strings.Contains(got, ids[0]) || !strings.Contains(got, ids[1]) || strings.Contains(got, "Z9") {
			t.Fatalf("pointer %q, want it to name %v only", got, ids)
		}
	})
}

// #2202: a form outside the list, quoting a box text that holds a request
// or a code, never reaches the agent as chat with that text in it.
func TestUnlistedReactionFormsNeverShowACodedText(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	id, err := r.ch.Request([]Item{lowItem("i1")}, 0)
	if err != nil {
		t.Fatal(err)
	}
	req := r.inbox()
	code := lowCodeRe.FindStringSubmatch(req)[2]
	for _, react := range []string{
		"Pinned “" + req + "”",
		"Emphasised “" + req + "”",
		"Removed a 👍 from “" + req + "”",
		"Marked as important “" + req[:30] + "…”",
		`Reply YES ` + id + ` ` + code + ` — "` + req + `"`,
	} {
		got := r.say(react)
		if strings.Contains(got, code) {
			t.Fatalf("reaction %q replied with the code: %q", react, got)
		}
	}
	for _, m := range r.agent.got() {
		if strings.Contains(m, code) || strings.Contains(m, "Reply YES") {
			t.Fatalf("agent got the request's text or code: %q", m)
		}
	}
	if len(r.agent.got()) != 5 {
		t.Fatalf("agent got %q, want 5 reaction events", r.agent.got())
	}
	if d := r.decisions(); len(d) != 0 {
		t.Fatalf("a reaction decided %v", d)
	}
	// A quote of a text with a code in it, not a request.
	r.ch.Converse("Your sign-in code is 482913 for the page.")
	r.inbox()
	r.say(`Pinned “Agent: Your sign-in code is 482913 for the page.”`)
	g := r.agent.got()
	if last := g[len(g)-1]; strings.Contains(last, "482913") {
		t.Fatalf("agent got the code: %q", last)
	}
}

// #2201: the owner's own text that starts like a reaction and holds a
// second quote is chat, delivered whole.
func TestOwnerTextWithInnerQuotesIsChat(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	r.say(`Liked "a" and "b"`)
	r.say(`Loved “the plan” or “the other plan”`)
	want := []string{`Liked "a" and "b"`, `Loved “the plan” or “the other plan”`}
	if got := r.agent.got(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("agent got %q, want the texts as chat %q", got, want)
	}
}
