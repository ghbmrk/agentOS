package owner

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
)

// REQ: CH-10, CH-12, CH-14
// TestUnicodeDigitChatCodeNeverReachesTheAgent: the live code typed in
// non-ASCII digits alone or in UNLOCK, locked, unlocked and challenged,
// never reaches the agent or the held queue, is never checked or counted,
// and never unlocks: the ASCII code stays unspent and still works
// afterwards. Each gets the fixed digits reply, as a non-ASCII RESUME code
// does (CTL-unicode-chat-code, #5458; reply #5616). Chat ending in such a
// code is TestNativeDigitTrailingTokenIsStripped.
func TestUnicodeDigitChatCodeNeverReachesTheAgent(t *testing.T) {
	forms := []struct {
		name string
		text func(code, token string) string
	}{
		{"code alone", func(c, _ string) string { return arabicIndic(c) }},
		{"UNLOCK, full-width", func(c, tok string) string { return "UNLOCK " + tok + " " + fullWidth(c) }},
		{"UNLOCK, arabic-indic", func(c, tok string) string { return "unlock " + tok + " " + arabicIndic(c) }},
	}
	for _, mode := range []string{"locked", "unlocked", "challenged"} {
		for _, f := range forms {
			t.Run(mode+"/"+f.name, func(t *testing.T) {
				r := newRig(t, nil)
				if mode == "unlocked" {
					r.unlock()
				}
				tok := "HKMP"
				if mode == "challenged" {
					r.ch.codes.st.Challenged = true
					r.ch.mu.Lock()
					tok = r.ch.codes.currentChallenge(r.clock())
					r.ch.mu.Unlock()
				}
				code := r.totp()
				text := f.text(code, tok)
				sent := len(r.agent.got())
				st := r.ch.codes.st
				wrong, held := len(st.Wrong), len(st.Waiting)
				got := r.say(text)
				if got != control.FoldedCodeReply {
					t.Fatalf("%q: %q, want the digits reply", text, got)
				}
				now := r.ch.codes.st
				if len(r.agent.got()) != sent || len(now.Wrong) != wrong || len(now.Waiting) != held {
					t.Fatalf("%q: passed on, counted or held: agent %v, wrong %d->%d, held %d->%d",
						text, r.agent.got(), wrong, len(now.Wrong), held, len(now.Waiting))
				}
				// The ASCII code was never checked, so it is unspent.
				switch mode {
				case "locked":
					if got := r.say(code); !strings.Contains(got, "code is right") {
						t.Fatalf("after %q the ASCII code: %q", text, got)
					}
				case "unlocked":
					r.say("thanks " + code)
					if a := r.agent.got(); len(a) != sent+1 || strings.Contains(a[len(a)-1], code) {
						t.Fatalf("after %q the ASCII code was not stripped: %v", text, a)
					}
				case "challenged":
					if got := r.say("UNLOCK " + tok + " " + code); !strings.Contains(got, "normally") {
						t.Fatalf("after %q the ASCII code: %q", text, got)
					}
				}
			})
		}
	}
}

// REQ: CH-14
// TestUnicodeNumberThatIsNotACodeStaysChat: non-ASCII digits that are not
// a separate trailing 6-digit token hold no code, so unlocked chat with
// them reaches the agent as sent (CTL-unicode-chat-code, #5458).
func TestUnicodeNumberThatIsNotACodeStaysChat(t *testing.T) {
	for _, text := range []string{
		"room " + arabicIndic("12"),
		"flight AB" + arabicIndic("482913"),
		"call " + fullWidth("1234567890"),
	} {
		r := newRig(t, nil)
		r.unlock()
		sent := len(r.agent.got())
		if got := r.say(text); got == control.UnclearReply || len(r.agent.got()) != sent+1 {
			t.Fatalf("%q: %q, agent %v; want it passed on as chat", text, got, r.agent.got())
		}
	}
}
