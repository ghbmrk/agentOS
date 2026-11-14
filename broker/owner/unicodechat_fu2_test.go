package owner

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
)

// REQ: CH-14
// TestEnclosedValuesMatchUnicode pins the first and last code point of
// every enclosed run to its Unicode numeric value (UnicodeData.txt 15.1,
// field 8), so the table cannot drift: U+1F10C, DINGBAT NEGATIVE CIRCLED
// SANS-SERIF DIGIT ZERO, is 0, not 1 (CTL-unicode-chat-code-fu2, #5650).
// An endpoint missing here fails too, so a new run must be pinned.
func TestEnclosedValuesMatchUnicode(t *testing.T) {
	want := map[rune]int{
		0x2460: 1, 0x2473: 20, // CIRCLED DIGIT ONE, CIRCLED NUMBER TWENTY
		0x2474: 1, 0x2487: 20, // PARENTHESIZED
		0x2488: 1, 0x249B: 20, // FULL STOP
		0x24EA: 0,              // CIRCLED DIGIT ZERO
		0x24EB: 11, 0x24F4: 20, // NEGATIVE CIRCLED NUMBER ELEVEN, TWENTY
		0x24F5: 1, 0x24FE: 10, // DOUBLE CIRCLED
		0x24FF: 0,             // NEGATIVE CIRCLED DIGIT ZERO
		0x2776: 1, 0x277F: 10, // DINGBAT NEGATIVE CIRCLED
		0x2780: 1, 0x2789: 10, // DINGBAT CIRCLED SANS-SERIF
		0x278A: 1, 0x2793: 10, // DINGBAT NEGATIVE CIRCLED SANS-SERIF
		0x3251: 21, 0x325F: 35, // CIRCLED NUMBER TWENTY ONE, THIRTY FIVE
		0x32B1: 36, 0x32BF: 50, // CIRCLED NUMBER THIRTY SIX, FIFTY
		0x1F100: 0,             // DIGIT ZERO FULL STOP
		0x1F101: 0, 0x1F10A: 9, // DIGIT ZERO COMMA, DIGIT NINE COMMA
		0x1F10B: 0, // DINGBAT CIRCLED SANS-SERIF DIGIT ZERO
		0x1F10C: 0, // DINGBAT NEGATIVE CIRCLED SANS-SERIF DIGIT ZERO
	}
	for _, e := range enclosed {
		for _, r := range []rune{e.lo, e.hi} {
			v, ok := want[r]
			if !ok {
				t.Errorf("U+%04X: enclosed run endpoint not pinned to a Unicode value", r)
				continue
			}
			if got := enclosedValue(r); got != v {
				t.Errorf("U+%04X: enclosedValue %d, Unicode numeric value %d", r, got, v)
			}
		}
	}
	if got := fold("🄌"); got != "0" {
		t.Errorf("fold(U+1F10C) = %q, want %q", got, "0")
	}
}

// REQ: CH-10, CH-12
// TestFoldedDigitsReplyOnlyForACodeRun: a RESUME, YES or NO with a number
// in other digits gets the digits reply only when, read through fold, it
// holds a 6-digit run, the length of a code; any other such number gets
// the unclear reply, since retyping it in 0-9 would not help. Neither
// reaches the agent or is counted (CTL-unicode-chat-code-fu2, #5650).
func TestFoldedDigitsReplyOnlyForACodeRun(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	code := r.totp()
	for _, c := range []struct{ text, want string }{
		{"Yes ② please", control.UnclearReply},
		{"no " + arabicIndic("2") + " thanks", control.UnclearReply},
		{"YES " + fullWidth("2"), control.UnclearReply},
		{"yes ½", control.UnclearReply},
		{"yes " + arabicIndic("1234567"), control.UnclearReply},
		{"YES " + arabicIndic(code), control.FoldedCodeReply},
		{"yes " + circled(code, "circled"), control.FoldedCodeReply},
		{"no " + code[:3] + fullWidth(code[3:]), control.FoldedCodeReply},
	} {
		sent := len(r.agent.got())
		wrongs := len(r.ch.codes.st.Wrong)
		if got := r.say(c.text); got != c.want || len(r.agent.got()) != sent || len(r.ch.codes.st.Wrong) != wrongs {
			t.Errorf("%q: %q, agent %v; want %q, nothing sent or counted", c.text, got, r.agent.got(), c.want)
		}
	}
}

// REQ: CH-10, CH-12, CH-14
// TestStrippedNativeNumberGetsANotice: unlocked, chat ending in a 6-digit
// token in other digits is forwarded without it, as before, and the owner
// is told once that the number was not sent and to use 0-9. The token is
// never checked or counted (CTL-unicode-chat-code-fu2, #5650, Potency 1).
func TestStrippedNativeNumberGetsANotice(t *testing.T) {
	r, f := newVerifierRig(t)
	r.unlock()
	code := r.totp()
	sent := len(r.agent.got())
	wrong, checks := len(r.ch.codes.st.Wrong), f.calls()
	got := r.say("order number " + arabicIndic("482913"))
	if a := r.agent.got(); len(a) != sent+1 || a[len(a)-1] != "order number" {
		t.Fatalf("agent got %v, want %q", a, "order number")
	}
	if strings.Count(got, control.StrippedNumberReply) != 1 {
		t.Fatalf("reply %q, want the stripped-number notice once", got)
	}
	if len(r.ch.codes.st.Wrong) != wrong || f.calls() != checks {
		t.Fatalf("the stripped token was checked or counted")
	}
	// The ASCII path is unchanged: a trailing number that is not the live
	// code passes on as sent, with no notice.
	other := "1" + code[1:]
	if code[0] == '1' {
		other = "2" + code[1:]
	}
	if got := r.say("order number " + other); strings.Contains(got, control.StrippedNumberReply) {
		t.Fatalf("ASCII number got the notice: %q", got)
	}
}

// REQ: CH-12
// TestStrippedNumberReplyIsOneGSM7Segment: the notice fits one plain
// segment and says what was cut and the next step.
func TestStrippedNumberReplyIsOneGSM7Segment(t *testing.T) {
	for _, r := range []string{control.StrippedNumberReply, control.FoldedCodeReply} {
		if len(r) > 160 || control.Fit(r) != r || strings.ContainsFunc(r, func(c rune) bool { return c > 0x7E }) {
			t.Fatalf("%q is not one plain segment", r)
		}
		if !strings.Contains(r, "0-9") || !strings.Contains(strings.ToLower(r), "not") {
			t.Fatalf("%q does not name the outcome and the next step", r)
		}
	}
}

// REQ: CH-10, CH-14
// TestStrippedNumberOnlyFromPlainChat: a 6-digit token in other digits is
// cut only from plain task chat. When what is left is empty, a control
// word or a reply (" ", "help", "retry", "pause g12"), the whole message
// gets the digits reply and nothing reaches the agent or is checked
// (CTL-unicode-chat-code-fu2, #5650; each case pins one guard in
// stripFoldedCode, the #5712 mutgate survivors among them).
func TestStrippedNumberOnlyFromPlainChat(t *testing.T) {
	r, f := newVerifierRig(t)
	r.unlock()
	n := arabicIndic("482913")
	for _, text := range []string{
		" " + n,          // nothing left before the token
		"help " + n,      // a control word
		"retry " + n,     // a reply that only the text before the token forms
		"pause g12 " + n, // the same, with an argument
	} {
		if rest, ok := stripFoldedCode(text); ok {
			t.Errorf("stripFoldedCode(%q) = %q, true; want the whole message kept out", text, rest)
		}
		sent, wrong, checks := len(r.agent.got()), len(r.ch.codes.st.Wrong), f.calls()
		if got := r.say(text); got != control.FoldedCodeReply || len(r.agent.got()) != sent ||
			len(r.ch.codes.st.Wrong) != wrong || f.calls() != checks {
			t.Errorf("%q: %q, agent %v; want %q, nothing sent, checked or counted", text, got, r.agent.got(), control.FoldedCodeReply)
		}
	}
}
