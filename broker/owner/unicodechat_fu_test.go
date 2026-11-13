package owner

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
)

// circled writes s's ASCII digits in one of the enclosed digit forms a
// phone's symbol keyboard offers: circled, parenthesised or negative
// circled (CTL-unicode-chat-code-fu, #5616).
func circled(s, form string) string {
	return strings.Map(func(r rune) rune {
		if r < '0' || r > '9' {
			return r
		}
		d := r - '0'
		switch form {
		case "circled":
			if d == 0 {
				return '⓪'
			}
			return '①' + d - 1
		case "parenthesised":
			if d == 0 {
				return '🄁' // DIGIT ZERO COMMA: no parenthesised zero exists
			}
			return '⑴' + d - 1
		default: // negative circled
			if d == 0 {
				return '⓿'
			}
			return '❶' + d - 1
		}
	}, s)
}

// REQ: CH-10, CH-14
// TestCircledDigitCodeNeverReachesTheAgent: the live code typed in
// circled, parenthesised or negative circled digits at the end of chat is
// stripped like any other trailing code: unlocked, the agent gets the rest
// without it; locked, the rest is held without it. It is never checked or
// counted (CTL-unicode-chat-code-fu, #5616, Security finding 1).
func TestCircledDigitCodeNeverReachesTheAgent(t *testing.T) {
	for _, form := range []string{"circled", "parenthesised", "negative"} {
		for _, mode := range []string{"locked", "unlocked"} {
			t.Run(mode+"/"+form, func(t *testing.T) {
				r := newRig(t, nil)
				if mode == "unlocked" {
					r.unlock()
				}
				code := r.totp()
				text := "book the table " + circled(code, form)
				sent := len(r.agent.got())
				st := r.ch.codes.st
				wrong, held := len(st.Wrong), len(st.Waiting)
				r.say(text)
				now := r.ch.codes.st
				if len(now.Wrong) != wrong {
					t.Fatalf("%q: counted as a wrong code", text)
				}
				switch mode {
				case "unlocked":
					a := r.agent.got()
					if len(a) != sent+1 || a[len(a)-1] != "book the table" {
						t.Fatalf("%q: agent got %v, want the rest without the code", text, a)
					}
				case "locked":
					if len(now.Waiting) != held+1 || now.Waiting[len(now.Waiting)-1].Text != "book the table" {
						t.Fatalf("%q: held %v, want the rest without the code", text, now.Waiting)
					}
					if len(r.agent.got()) != sent {
						t.Fatalf("%q: reached the agent while locked", text)
					}
				}
			})
		}
	}
}

// REQ: CH-10, CH-14
// TestNativeDigitTrailingTokenIsStripped: chat ending in a separate
// 6-digit token in non-ASCII digits is routed as the ASCII path routes
// chat with a trailing code, with the token stripped and never checked:
// unlocked, the agent gets the rest; locked, the rest is held. The token
// is never counted, and the live ASCII code stays unspent afterwards
// (CTL-unicode-chat-code-fu, #5616, Potency and UX finding 2).
func TestNativeDigitTrailingTokenIsStripped(t *testing.T) {
	forms := []struct {
		name string
		text func(code string) string
		rest string
	}{
		{"arabic-indic order number", func(string) string { return "order number " + arabicIndic("482913") }, "order number"},
		{"arabic-indic live code", func(c string) string { return "book the table " + arabicIndic(c) }, "book the table"},
		{"full-width live code, full stop", func(c string) string { return "book the table " + fullWidth(c) + "." }, "book the table"},
		{"one digit folded", func(c string) string { return "book the table " + c[:5] + arabicIndic(c[5:]) }, "book the table"},
	}
	for _, mode := range []string{"locked", "unlocked"} {
		for _, f := range forms {
			t.Run(mode+"/"+f.name, func(t *testing.T) {
				r := newRig(t, nil)
				if mode == "unlocked" {
					r.unlock()
				}
				code := r.totp()
				text := f.text(code)
				sent := len(r.agent.got())
				st := r.ch.codes.st
				wrong, held := len(st.Wrong), len(st.Waiting)
				if got := r.say(text); got == control.UnclearReply || got == control.FoldedCodeReply {
					t.Fatalf("%q: %q, want it routed as chat", text, got)
				}
				now := r.ch.codes.st
				if len(now.Wrong) != wrong {
					t.Fatalf("%q: counted as a wrong code", text)
				}
				switch mode {
				case "unlocked":
					a := r.agent.got()
					if len(a) != sent+1 || a[len(a)-1] != f.rest {
						t.Fatalf("%q: agent got %v, want %q", text, a, f.rest)
					}
					r.say("thanks " + code)
					if a := r.agent.got(); len(a) != sent+2 || strings.Contains(a[len(a)-1], code) {
						t.Fatalf("after %q the ASCII code was not stripped (spent?): %v", text, a)
					}
				case "locked":
					if len(r.agent.got()) != sent {
						t.Fatalf("%q: reached the agent while locked", text)
					}
					if len(now.Waiting) != held+1 || now.Waiting[len(now.Waiting)-1].Text != f.rest {
						t.Fatalf("%q: held %v, want %q", text, now.Waiting, f.rest)
					}
					if got := r.say(code); !strings.Contains(got, "code is right") {
						t.Fatalf("after %q the ASCII code: %q", text, got)
					}
				}
			})
		}
	}
}

// REQ: CH-10
// TestNativeDigitTokenAfterAnotherIsNotForwarded: stripping the last
// folded token never forwards an earlier one; the message is quarantined
// instead (CTL-unicode-chat-code-fu, #5616).
func TestNativeDigitTokenAfterAnotherIsNotForwarded(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	code := r.totp()
	sent := len(r.agent.got())
	text := "book " + arabicIndic(code) + " " + arabicIndic(code)
	if got := r.say(text); got != control.FoldedCodeReply || len(r.agent.got()) != sent {
		t.Fatalf("%q: %q, agent %v; want the digits reply and nothing sent", text, got, r.agent.got())
	}
}

// REQ: CH-12
// TestFoldedCodeReplyIsOneGSM7Segment: the digits reply fits one GSM-7
// segment and says both the cause and that nothing was sent.
func TestFoldedCodeReplyIsOneGSM7Segment(t *testing.T) {
	r := control.FoldedCodeReply
	if len(r) > 160 || control.Fit(r) != r {
		t.Fatalf("%q is not one plain segment", r)
	}
	for _, r := range r {
		if r > 0x7E {
			t.Fatalf("non-ASCII %q in the reply", r)
		}
	}
	if !strings.Contains(r, "0-9") || !strings.Contains(r, "not sent to your agent") {
		t.Fatalf("%q does not name the cause and the outcome", r)
	}
}
