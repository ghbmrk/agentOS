package owner

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-15, CH-19
// A reply to the owner's message is conversation: in quiet hours with
// the hour's texts spent it goes at once, behind the agent prefix, is
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
	if len(got) != 2 || got[0] != AgentPrefix+"Your invoice is drafted." || got[1] != Hidden {
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
	if err := r.ch.Converse("Done 👍\nSee you at 3"); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("Sure 👩‍💻 ", 60)
	if err := r.ch.Converse(long); err != nil {
		t.Fatal(err)
	}
	got := r.sentTexts()
	if len(got) != 2 || got[0] != AgentPrefix+"Done 👍\nSee you at 3" {
		t.Fatalf("Converse sent %q", got)
	}
	if n, gsm7 := modem.Segments(got[1]); gsm7 || n != control.Segments || !strings.HasPrefix(long, strings.TrimPrefix(got[1], AgentPrefix)) {
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
	if got := r.sentTexts(); len(got) != 1 || got[0] != AgentPrefix+"Booked 🎉\nThursday 9am" {
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
	if got := r.sentTexts(); len(got) != 1 || got[0] != AgentPrefix+"Booked Thursday 9am" {
		t.Fatalf("sent %q", got)
	}
}
