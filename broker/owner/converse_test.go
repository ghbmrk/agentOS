package owner

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-15, CH-19
// A reply to the owner's message is conversation: in quiet hours with
// the hour's texts spent it goes at once, with no label, is
// never held and spends nothing. A secret-shaped reply still becomes the
// pointer.
func TestConverseIsNeverPaced(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	for i := 0; i < DefaultTextsPerHour; i++ {
		if err := r.ch.Post(ClassSecurity, "Security alert."); err != nil {
			t.Fatal(err)
		}
	}
	r.sentTexts()
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance %d, want spent", a)
	}
	if err := r.ch.Converse("Your invoice is drafted."); err != nil {
		t.Fatal(err)
	}
	if err := r.ch.Converse("Your login code is 482913."); err != nil {
		t.Fatal(err)
	}
	got := r.sentTexts()
	if len(got) != 2 || got[0] != "Your invoice is drafted." || got[1] != Hidden {
		t.Fatalf("Converse in quiet hours sent %q, want the prefixed reply and the pointer", got)
	}
	if len(r.held()) != 0 {
		t.Fatalf("held %d, want none", len(r.held()))
	}
	r.ch.mu.Lock()
	n := len(r.ch.codes.st.Sent)
	r.ch.mu.Unlock()
	if n != DefaultTextsPerHour {
		t.Fatalf("%d sends counted, want %d: conversation counted", n, DefaultTextsPerHour)
	}
}

// REQ: CH-12
// TestCH12ConverseSendsEmojiWhole: an agent reply keeps its emoji and line
// breaks, goes as UCS-2 within three segments, a held agent text keeps
// them through the hold, and the control and bidi characters are gone
// before the reaction and CH-19 checks read the text.
func TestCH12ConverseSendsEmojiWhole(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	r.ucs2 = true
	if err := r.ch.Converse("Done 👍\nSee you at 3"); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("Sure 👩‍💻 ", 60)
	if err := r.ch.Converse(long); err != nil {
		t.Fatal(err)
	}
	got := r.sentTexts()
	if len(got) != 2 || got[0] != "Done 👍\nSee you at 3" {
		t.Fatalf("Converse sent %q", got)
	}
	if n, gsm7 := modem.Segments(got[1]); gsm7 || n != control.Segments || !strings.HasPrefix(long, got[1]) {
		t.Fatalf("long emoji reply: %d segments, gsm7 %v", n, gsm7)
	}
	if strings.Count(got[1], "👩") != strings.Count(got[1], "💻") {
		t.Fatal("a joined emoji was split")
	}

	// Stripped first: an override cannot hide a reaction form or a code.
	if err := r.ch.Converse("\u202ELiked \u201cYour invoice is drafted.\u201d"); !errors.Is(err, ErrAgentReaction) {
		t.Fatalf("bidi-wrapped reaction: %v, want ErrAgentReaction", err)
	}
	if err := r.ch.Converse("Your login code is 48\u20662\u2069913\u0007."); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != Hidden {
		t.Fatalf("a code split by controls went out as %q", got)
	}

	// Held through quiet hours, the agent text still keeps its emoji.
	if err := r.ch.Notify("Booked 🎉\nThursday 9am"); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 0 {
		t.Fatalf("sent in quiet hours: %q", got)
	}
	r.advance(8*time.Hour + time.Minute)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != "Booked 🎉\nThursday 9am" {
		t.Fatalf("released %q", got)
	}
}

// gapControls are the controls a reply might put between a code word and
// its code; stripped, each must still leave the two apart (#2346).
var gapControls = []string{"\r", "\v", "\f", "\u0085", "\x01", "\u202E", "\u2066", "\u2067", "\u2068", "\u2069", "\u200F"}

// bidiControls are the bidi controls StripControls removes with no gap.
var bidiControls = []string{"\u202A", "\u202B", "\u202C", "\u202D", "\u202E", "\u2066", "\u2067", "\u2068", "\u2069", "\u200E", "\u200F", "\u061C"}

// TestCH12BidiInsideATokenStillWithholds: a bidi control inside a key or a
// short code does not split it past CH-19 on any agent path (CH-19,
// CH-12, #2346).
func TestCH12BidiInsideATokenStillWithholds(t *testing.T) {
	for _, bidi := range bidiControls {
		for _, text := range []string{
			"sk-abcdefghij" + bidi + "klmnopqrstuvwx",
			"AKIAABCDEFGH" + bidi + "IJKLMNOP",
			"code AB" + bidi + "C1",
		} {
			for name, send := range map[string]func(*Channel) error{
				"Converse":  func(c *Channel) error { return c.Converse(text) },
				"NotifyAs":  func(c *Channel) error { return c.NotifyAs(ClassAgent, text) },
				"NotifyNow": func(c *Channel) error { return c.NotifyNow(text) },
			} {
				r := pacedRig(t, quiet22to7(), 12, 0)
				if err := send(r.ch); err != nil {
					t.Fatalf("%s %q: %v", name, text, err)
				}
				if got := r.sentTexts(); len(got) != 1 || got[0] != Hidden {
					t.Errorf("%s %q sent %q", name, text, got)
				}
			}
		}
	}
}

// TestCH12ControlGapStillWithholdsCode: a code word and a code joined only
// by a stripped control are still withheld on every agent path (CH-19,
// CH-12, #2346).
func TestCH12ControlGapStillWithholdsCode(t *testing.T) {
	for _, gap := range gapControls {
		text := "Your code" + gap + "482913"
		if !AgentSecret(text) {
			t.Errorf("%q: not secret-shaped", text)
		}
		for name, send := range map[string]func(*Channel) error{
			"Converse":  func(c *Channel) error { return c.Converse(text) },
			"NotifyAs":  func(c *Channel) error { return c.NotifyAs(ClassAgent, text) },
			"NotifyNow": func(c *Channel) error { return c.NotifyNow(text) },
		} {
			r := pacedRig(t, quiet22to7(), 12, 0)
			if err := send(r.ch); err != nil {
				t.Fatalf("%s %q: %v", name, text, err)
			}
			if got := r.sentTexts(); len(got) != 1 || got[0] != Hidden {
				t.Errorf("%s %q sent %q", name, text, got)
			}
		}
	}
}

// TestCH12CcInsideATokenStillWithholds: a key or a short code a Cc control
// splits mid-token (the Cc in gapControls, NUL and a C1 control) is
// withheld on every agent path: CH-19 also reads the text with the control
// removed and no gap (control.JoinControls, CH-19, CH-12, #2346).
func TestCH12CcInsideATokenStillWithholds(t *testing.T) {
	var cc []string
	for _, g := range gapControls {
		if r := []rune(g)[0]; unicode.Is(unicode.Cc, r) {
			cc = append(cc, g)
		}
	}
	for _, g := range append(cc, "\x00", "\u0080", "\x7f") {
		for _, text := range []string{
			"key sk-abcdefghij" + g + "klmnopqrstuvwx",
			"AKIAABCDEFGH" + g + "IJKLMNOP",
			"token ghp_abcdefghijklmn" + g + "opqrstuvwxyz0123456789",
			"key: eyJhbGciOi" + g + ".eyJzdWIiOi.SflKxwRJSM",
			"code AB" + g + "C1",
			"code A" + g + "1B2",
		} {
			if !AgentSecret(text) {
				t.Errorf("%q: not secret-shaped", text)
			}
			for name, send := range map[string]func(*Channel) error{
				"Converse":  func(c *Channel) error { return c.Converse(text) },
				"NotifyAs":  func(c *Channel) error { return c.NotifyAs(ClassAgent, text) },
				"NotifyNow": func(c *Channel) error { return c.NotifyNow(text) },
			} {
				r := pacedRig(t, quiet22to7(), 12, 0)
				if err := send(r.ch); err != nil {
					t.Fatalf("%s %q: %v", name, text, err)
				}
				if got := r.sentTexts(); len(got) != 1 || got[0] != Hidden {
					t.Errorf("%s %q sent %q", name, text, got)
				}
			}
		}
	}

	// Plain text with a Cc in it still goes, the gap a space.
	r := pacedRig(t, quiet22to7(), 12, 0)
	if err := r.ch.Converse("Booked\x01Thursday 9am"); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != "Booked Thursday 9am" {
		t.Fatalf("sent %q", got)
	}
}

// REQ: CH-15
// TestCH15WindowOpenRepliesUnpaced: owner task chat that reached the
// agent opens the chat; five minutes later, in quiet hours with the
// hour's texts spent, the chat is still open and a reply in it goes at
// once and spends nothing.
func TestCH15WindowOpenRepliesUnpaced(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	r.unlock()
	r.say("book a table for two")
	if len(r.agent.got()) != 1 {
		t.Fatalf("task chat did not reach the agent: %q", r.agent.got())
	}
	for i := 0; i < DefaultTextsPerHour; i++ {
		if err := r.ch.Post(ClassSecurity, "Security alert."); err != nil {
			t.Fatal(err)
		}
	}
	r.sentTexts()
	r.advance(5 * time.Minute)
	if !r.ch.ChatOpen() {
		t.Fatal("the chat closed five minutes after the owner's message")
	}
	if err := r.ch.Converse("Booked for 8pm."); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != "Booked for 8pm." {
		t.Fatalf("reply in the open chat: %q, want it sent at once", got)
	}
	if a := r.ch.Allowance(r.clock()); a != 0 {
		t.Fatalf("allowance %d after a reply in the chat, want it unspent at 0", a)
	}
	if len(r.held()) != 0 {
		t.Fatalf("reply in the open chat held: %+v", r.held())
	}
}

// REQ: CH-15
// TestCH15WindowEdge: the chat is open at 29:59 after the owner's last
// message that reached the agent and closed at 30:01; a new owner message
// re-opens it; under CHAT 60 it lasts an hour.
func TestCH15WindowEdge(t *testing.T) {
	r := newRig(t, nil)
	r.ch = r.open()
	if r.ch.ChatOpen() {
		t.Fatal("chat open before any owner message")
	}
	r.unlock()
	if r.ch.ChatOpen() {
		t.Fatal("the unlock code opened the chat")
	}
	r.say("book a table")
	r.advance(29*time.Minute + 59*time.Second)
	if !r.ch.ChatOpen() {
		t.Fatal("chat closed at 29:59")
	}
	r.advance(2 * time.Second)
	if r.ch.ChatOpen() {
		t.Fatal("chat open at 30:01")
	}
	r.say("and a taxi at 7")
	if !r.ch.ChatOpen() {
		t.Fatal("a new owner message did not re-open the chat")
	}
	if got := r.say("CHAT 60"); !strings.HasPrefix(got, "Chat set: 60 minutes.") {
		t.Fatalf("CHAT 60: %q", got)
	}
	r.say("make it 8")
	r.advance(59*time.Minute + 59*time.Second)
	if !r.ch.ChatOpen() {
		t.Fatal("chat closed at 59:59 under CHAT 60")
	}
	r.advance(2 * time.Second)
	if r.ch.ChatOpen() {
		t.Fatal("chat open at 60:01 under CHAT 60")
	}
}

// REQ: CH-15
// TestCH15WindowSettingBounds: CHAT takes 5 to 240 minutes, only in an
// unlocked session; a value out of range gets the forms and changes
// nothing; the setting survives a restart, and a saved value out of range
// fails closed to the default.
func TestCH15WindowSettingBounds(t *testing.T) {
	r := newRig(t, nil)
	r.ch = r.open()
	if got := r.say("CHAT 60"); strings.HasPrefix(got, "Chat set") {
		t.Fatalf("locked CHAT 60 took effect: %q", got)
	}
	if w := r.ch.ChatWindow(); w != DefaultChatMinutes*time.Minute {
		t.Fatalf("window %v by default, want %d minutes", w, DefaultChatMinutes)
	}
	r.unlock()
	for _, bad := range []string{"CHAT 0", "CHAT 4", "CHAT 241", "CHAT 1000"} {
		if got := r.say(bad); got != pacingForms {
			t.Fatalf("%s: %q", bad, got)
		}
	}
	if w := r.ch.ChatWindow(); w != DefaultChatMinutes*time.Minute {
		t.Fatalf("a refused CHAT changed the window to %v", w)
	}
	for _, n := range []int{MinChatMinutes, MaxChatMinutes} {
		got := r.say(fmt.Sprintf("chat %d", n))
		if !strings.HasPrefix(got, fmt.Sprintf("Chat set: %d minutes.", n)) {
			t.Fatalf("CHAT %d: %q", n, got)
		}
		if w := r.ch.ChatWindow(); w != time.Duration(n)*time.Minute {
			t.Fatalf("window %v after CHAT %d", w, n)
		}
	}
	if st, _ := r.store.Load(); st.Pacing.ChatMinutes != MaxChatMinutes {
		t.Fatalf("CHAT %d not saved: %+v", MaxChatMinutes, st.Pacing)
	}
	if again := newRig(t, r.store); again.ch.ChatWindow() != MaxChatMinutes*time.Minute {
		t.Fatalf("CHAT %d lost on restart: %v", MaxChatMinutes, again.ch.ChatWindow())
	}
	if !strings.Contains(pacingHelp, "CHAT") || !strings.Contains(pacingForms, "CHAT 5 to 240") {
		t.Fatalf("HELP or the forms do not name CHAT: %q / %q", pacingHelp, pacingForms)
	}
	for _, m := range []int{-1, 1, 4, 241} {
		if (Pacing{ChatMinutes: m}).valid() {
			t.Fatalf("a saved CHAT of %d minutes is valid", m)
		}
	}
}
