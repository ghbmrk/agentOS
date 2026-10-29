package owner

// REQ: CH-21, A14

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// codeAsks are agent texts CH-21 withholds: a word of the vocabulary, the
// reply grammar, the reply-options footer, and the same split by a
// control character or folded.
var codeAsks = []string{
	"To finish, send me the code your bank texted you.",
	"Reply YES K7 to approve.",
	"Text STOP 4829 now.",
	"Reply yes to go on, or no to stop.",
	"Please send your pass\x01word here.",
	"Reply YES\x07 K7 to approve.",
	"ΥΕЅ Α7",
	"What is your PIN?",
	"I need the one-time number from the email.",
	"Text me the codes your bank sent.",
	"What are your passwords?",
	"Send both PINs.",
	"Paste the OTPs here.",
	"Send both ΡΙΝs.",
}

// TestCodeAskIsHeldNotPacked: agent text that asks for a code or takes the
// reply grammar never reaches the owner. Each of Converse, Notify and
// NotifyNow sends the fixed HeldCode text instead, with no agent prefix
// and nothing of the agent's text, and not packed with other texts.
func TestCodeAskIsHeldNotPacked(t *testing.T) {
	for _, ask := range codeAsks {
		for name, send := range map[string]func(*Channel, string) error{
			"Converse":  (*Channel).Converse,
			"Notify":    (*Channel).Notify,
			"NotifyNow": (*Channel).NotifyNow,
		} {
			r := pacedRig(t, quiet22to7(), 12, 0)
			if err := send(r.ch, ask); err != nil {
				t.Fatalf("%s(%q): %v", name, ask, err)
			}
			got := r.sentTexts()
			if len(got) != 1 || got[0] != HeldCode {
				t.Fatalf("%s(%q) sent %q, want only %q", name, ask, got, HeldCode)
			}
		}
	}
}

// TestCodeAskHeldInQuietHoursStaysHeld: a held text waiting for quiet
// hours to end is the fixed text too, so the release cannot send the
// agent's words.
func TestCodeAskHeldInQuietHoursStaysHeld(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	if err := r.ch.Notify("Reply YES K7 482 to approve."); err != nil {
		t.Fatal(err)
	}
	if h := r.held(); len(h) != 1 || h[0].Text != HeldCode {
		t.Fatalf("held %+v, want the fixed text", h)
	}
	r.advance(8 * time.Hour)
	if err := r.ch.Release(); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || !strings.HasSuffix(got[0], HeldCode) || strings.Contains(got[0], "YES") {
		t.Fatalf("released %q", got)
	}
}

// TestOrdinaryAgentTextPasses: text free of the vocabulary and the reply
// grammar goes as before, behind the agent prefix.
func TestOrdinaryAgentTextPasses(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 12, 0)
	for _, s := range []string{"Lunch is booked for noon.", "Yes, the hedge is done.", "No rush on the hedge."} {
		if err := r.ch.Converse(s); err != nil {
			t.Fatal(err)
		}
		if got := r.sentTexts(); len(got) != 1 || got[0] != AgentPrefix+s {
			t.Fatalf("Converse(%q) sent %q", s, got)
		}
	}
}

// TestSecretStillWinsOverHold: a secret-shaped text keeps CH-19's pointer.
func TestSecretStillWinsOverHold(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 12, 0)
	if err := r.ch.Converse("Your login code is 482913."); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != Hidden {
		t.Fatalf("sent %q, want the CH-19 pointer", got)
	}
}

// TestHeldCodeIsTheSpecWording: until #890 keeps held text, the fixed
// text is CH-21's could-not-be-kept text: it opens as CH-21's held text
// does, fits one GSM-7 segment, points to no page that lacks the text
// (CH-12), and is itself not held again.
func TestHeldCodeIsTheSpecWording(t *testing.T) {
	b, err := os.ReadFile("../../SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	const opening = "I held back a message because it mentioned a code"
	if !strings.Contains(string(b), `"`+opening) || !strings.HasPrefix(HeldCode, opening) {
		t.Fatalf("HeldCode %q does not open as CH-21's held text", HeldCode)
	}
	if !strings.Contains(HeldCode, "could not keep") || strings.Contains(HeldCode, "Wi-Fi page") {
		t.Fatalf("HeldCode %q points to a page that does not keep the text", HeldCode)
	}
	if n, gsm := modem.Segments(HeldCode); !gsm || n != 1 {
		t.Fatalf("HeldCode is %d segments (GSM-7 %v)", n, gsm)
	}
	if got := agentText(HeldCode); got != HeldCode {
		t.Fatalf("agentText(HeldCode) = %q", got)
	}
}
