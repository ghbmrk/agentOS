package owner

// REQ: CH-12, CH-19

import (
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/ghbmrk/agentos/broker/modem"
)

// TestAgentTextKeepsEmojiAndLineBreaks: agent conversation keeps its emoji
// and line breaks and goes in UCS-2 rather than being rewritten to GSM-7
// (CH-12, #2188's failure path "Done ?See you at 3").
func TestAgentTextKeepsEmojiAndLineBreaks(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	for _, in := range []string{"Done 👍\nSee you at 3", "Pushed 👩‍💻 ✅", "Two lines\nno emoji"} {
		if err := r.ch.Converse(in); err != nil {
			t.Fatal(err)
		}
	}
	got := r.sentTexts()
	want := []string{AgentPrefix + "Done 👍\nSee you at 3", AgentPrefix + "Pushed 👩‍💻 ✅", AgentPrefix + "Two lines\nno emoji"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("sent %q, want %q", got, want)
	}
	if _, gsm7 := modem.Segments(got[0]); gsm7 {
		t.Fatal("the emoji text was counted as GSM-7")
	}
	if _, gsm7 := modem.Segments(got[2]); !gsm7 {
		t.Fatal("a line break pushed a plain text to UCS-2")
	}
}

// TestAgentTextStripsControlsAndBidi: Cc characters other than LF and the
// bidi controls are removed before sending; joiners and variation selectors
// stay (CH-12).
func TestAgentTextStripsControlsAndBidi(t *testing.T) {
	in := "a\tb\rc\x00d\x1b\u0085e‮f‪g⁦h⁩i‎j‏k؜l\nm 👩‍💻 ❤️"
	want := "abcdefghijkl\nm 👩‍💻 ❤️"
	if got := CleanAgentText(in); got != want {
		t.Fatalf("CleanAgentText = %q, want %q", got, want)
	}
	r := pacedRig(t, quiet22to7(), 23, 0)
	if err := r.ch.Converse(in); err != nil {
		t.Fatal(err)
	}
	if got := r.sentTexts(); len(got) != 1 || got[0] != AgentPrefix+want {
		t.Fatalf("sent %q", got)
	}
}

// TestBidiSplitCodeIsStillHidden: a code broken up by direction controls
// reads as one code on the phone, so it is checked as one: the controls go
// before CH-19's check, and the text becomes the pointer (CH-12, CH-19).
func TestBidiSplitCodeIsStillHidden(t *testing.T) {
	r := pacedRig(t, quiet22to7(), 23, 0)
	for _, in := range []string{"Your login code is 48‮29‬13 👍", "Your login code is 4‏8⁦2⁩91\u00003"} {
		if err := r.ch.Converse(in); err != nil {
			t.Fatal(err)
		}
	}
	if got := r.sentTexts(); len(got) != 2 || got[0] != Hidden || got[1] != Hidden {
		t.Fatalf("sent %q, want the pointer twice", got)
	}
}

// TestRoomCountsTheEncoding: Room gives the GSM-7 room for plain text and
// UCS-2's 201 units once an emoji is in, counting extension characters as
// two septets and an emoji as two units (CH-12).
func TestRoomCountsTheEncoding(t *testing.T) {
	plain := strings.Repeat("a", 600)
	if got := Room(plain, ""); got != 3*153-len(AgentPrefix) {
		t.Fatalf("plain room %d", got)
	}
	ext := strings.Repeat("{", 600)
	if got := Room(ext, ""); got != (3*153-len(AgentPrefix))/2 {
		t.Fatalf("extension room %d", got)
	}
	emoji := "👍" + strings.Repeat("a", 600)
	p := Room(emoji, "")
	units := len(utf16.Encode([]rune(AgentPrefix + emoji[:p])))
	if units != 3*67 {
		t.Fatalf("emoji room %d bytes, %d units", p, units)
	}
	if got := Room("short 👍", ""); got != len("short 👍") {
		t.Fatalf("a short text's room %d", got)
	}
	// An emoji is never split.
	run := strings.Repeat("👍", 200)
	if p := Room(run, ""); p%len("👍") != 0 {
		t.Fatalf("room %d cuts an emoji", p)
	}
	if p := Room(plain, " tail"); p != 3*153-len(AgentPrefix)-len(" tail") {
		t.Fatalf("room with suffix %d", p)
	}
}

// TestLongPushStaysWithinOneText: a push longer than three segments in its
// own encoding still goes as one text within the limit (CH-12).
func TestLongPushStaysWithinOneText(t *testing.T) {
	r := pacedRig(t, Pacing{}, 12, 0)
	if err := r.ch.NotifyNow(strings.Repeat("Ready 👍 ", 60)); err != nil {
		t.Fatal(err)
	}
	got := r.sentTexts()
	if len(got) != 1 {
		t.Fatalf("%d texts", len(got))
	}
	if n, _ := modem.Segments(got[0]); n > 3 {
		t.Fatalf("push took %d segments", n)
	}
}
