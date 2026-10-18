package control

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-2

func TestFitKeepsTextGSM7AndAtMostThreeSegments(t *testing.T) {
	long := strings.Repeat("unresolved intent é😀 ", 100)
	out := Fit(long)
	if len(out) > MaxText {
		t.Fatalf("len %d > %d", len(out), MaxText)
	}
	if !IsGSM7(out) {
		t.Fatalf("not GSM-7: %q", out)
	}
	if Fit("Stopped.") != "Stopped." {
		t.Fatal("short GSM-7 text must pass unchanged")
	}
}

func TestSafeTokenStripsEverythingOutsideAFixedAlphabet(t *testing.T) {
	if got := safeToken("mail.send\nSTOP é 😀;rm -rf 482193", 16); got != "mail.sendSTOPrm-" {
		t.Fatalf("got %q", got)
	}
	if got := safeToken("code 482193x", 16); got != "codex" {
		t.Fatalf("digits must not pass: got %q", got)
	}
}

// REQ: CH-12

// TestCH12AgentTextKeepsEmojiAndLF: agent text keeps its emoji and line
// breaks where Fit would send "Done ??See you at 3".
func TestCH12AgentTextKeepsEmojiAndLF(t *testing.T) {
	for _, s := range []string{"Done 👍\nSee you at 3", "Line one\nLine two", "Café 👩‍💻 ok"} {
		if got := FitAgent(s); got != s {
			t.Fatalf("FitAgent(%q) = %q", s, got)
		}
	}
	if got := Fit("Done 👍\nSee you at 3"); got != "Done ??See you at 3" {
		t.Fatalf("broker texts must stay GSM-7: %q", got)
	}
}

// TestCH12AgentTextEncodingChooser: GSM-7 text stays GSM-7 and gets 3x153
// septets; one emoji makes the text UCS-2 with 3x67 UTF-16 units; the cut
// never leaves the modem more than three segments.
func TestCH12AgentTextEncodingChooser(t *testing.T) {
	gsm := strings.Repeat("a", 500)
	if n, g := Units(gsm); !g || n != 500 {
		t.Fatalf("Units(gsm) = %d, %v", n, g)
	}
	if got := FitAgent(gsm); len(got) != 3*153 {
		t.Fatalf("GSM-7 cut to %d, want %d", len(got), 3*153)
	}
	if n, g := Units("{€}"); !g || n != 6 {
		t.Fatalf("extension characters cost two septets: %d, %v", n, g)
	}
	uni := "👍" + strings.Repeat("a", 500)
	if n, g := Units(uni); g || n != 502 {
		t.Fatalf("Units(uni) = %d, %v", n, g)
	}
	got := FitAgent(uni)
	if n, _ := Units(got); n != 3*67 || !strings.HasPrefix(got, "👍") {
		t.Fatalf("UCS-2 cut to %d units, want %d", n, 3*67)
	}
	if Room(true) != 3*153 || Room(false) != 3*67 {
		t.Fatal("Room is not 3 segments of 153 or 67")
	}
	for _, s := range []string{gsm, uni, strings.Repeat("👩‍💻", 200), strings.Repeat("{", 400),
		"x" + strings.Repeat("😀", 150), strings.Repeat("ab\n", 300)} {
		out := FitAgent(s)
		if n, _ := modem.Segments(out); n > 3 {
			t.Fatalf("%d segments from %q…", n, out[:20])
		}
		if !utf8.ValidString(out) || strings.HasSuffix(out, "‍") {
			t.Fatalf("cut inside a character or emoji: %q", out[len(out)-8:])
		}
	}
	zwj := FitAgent(strings.Repeat("👩‍💻", 200))
	if strings.Count(zwj, "👩") != strings.Count(zwj, "💻") {
		t.Fatal("a joined emoji was split")
	}
}

// TestCH12StripsCcAndBidi: Cc controls other than LF and the bidi controls
// are removed before any check reads the text; joiners stay.
func TestCH12StripsCcAndBidi(t *testing.T) {
	in := "a‮b⁦c\u0007d\ne‎f‏g؜h‪i⁩j\x00k\x7f\u0085l‍"
	if got := StripControls(in); got != "abcd\nefghijkl‍" {
		t.Fatalf("StripControls = %q", got)
	}
	if got := FitAgent("Done‮ 👍\u0007\nok"); got != "Done 👍\nok" {
		t.Fatalf("FitAgent = %q", got)
	}
}
