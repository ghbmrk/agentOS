package owner

import (
	"errors"
	"strings"
	"testing"
	"time"

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
