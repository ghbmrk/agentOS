package owner

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
)

// REQ: CH-2, CH-11, CH-14

// fullWidth writes s's ASCII letters and digits in their full-width forms.
func fullWidth(s string) string {
	return strings.Map(func(r rune) rune {
		if r > ' ' && r < 0x7F {
			return r + 0xFEE0
		}
		return r
	}, s)
}

// TestEveryStopFormStopsAndLeaksNoCode: a message that is STOP with only
// codes, in any form a phone or a hurried owner may send, is STOP, locked,
// unlocked and challenged. It stops, counts in the STOP generation, voids
// an earlier RESUME code, and its codes are never checked, spent, counted,
// echoed or passed on: the agent gets nothing, and the wrong-code count,
// the unlock window, the last code step, challenge mode and any held
// message are unchanged (SEC-stop-forms, #2475).
func TestEveryStopFormStopsAndLeaksNoCode(t *testing.T) {
	forms := []struct {
		name string
		text func(c, c2 string) string
	}{
		{"bare", func(c, c2 string) string { return "STOP" }},
		{"space", func(c, c2 string) string { return "STOP " + c }},
		{"comma", func(c, c2 string) string { return "STOP," + c }},
		{"dash", func(c, c2 string) string { return "STOP-" + c }},
		{"dot", func(c, c2 string) string { return "STOP." + c }},
		{"code first", func(c, c2 string) string { return c + " STOP" }},
		{"lower case", func(c, c2 string) string { return "stop " + c }},
		{"5 digits", func(c, c2 string) string { return "STOP " + c[:5] }},
		{"7 digits", func(c, c2 string) string { return "STOP " + c + "1" }},
		{"8 digits", func(c, c2 string) string { return "STOP 12345678" }},
		{"8 digits live", func(c, c2 string) string { return "STOP " + c + "12" }},
		{"two codes", func(c, c2 string) string { return "STOP " + c + " " + c2 }},
		{"full-width word", func(c, c2 string) string { return fullWidth("STOP") }},
		{"full-width word and code", func(c, c2 string) string { return fullWidth("STOP " + c) }},
		{"full-width digits", func(c, c2 string) string { return "STOP " + fullWidth(c) }},
		{"grid cell", func(c, c2 string) string { return "STOP H3" }},
		{"grid cell lower case", func(c, c2 string) string { return "stop j10" }},
		{"grid cell and code", func(c, c2 string) string { return "STOP H3 " + c }},
		{"pound sign", func(c, c2 string) string { return "STOP £ " + c }},
		{"euro sign", func(c, c2 string) string { return "STOP €" + c }},
		{"yen sign", func(c, c2 string) string { return "¥STOP " + c }},
		{"glued code", func(c, c2 string) string { return "STOP" + c }},
		{"glued code first", func(c, c2 string) string { return c + "STOP" }},
		{"glued both sides", func(c, c2 string) string { return c + "stop" + c2 }},
		{"glued and spaced", func(c, c2 string) string { return "STOP" + c + " " + c2 }},
		{"glued full-width", func(c, c2 string) string { return fullWidth("STOP" + c) }},
		{"glued grid cell", func(c, c2 string) string { return "STOPH3" }},
		{"zero-width inside", func(c, c2 string) string { return "ST\u200bOP " + c }},
		{"combining mark", func(c, c2 string) string { return "STO\u0301P," + c }},
	}
	for _, mode := range []string{"locked", "unlocked", "challenged"} {
		for _, f := range forms {
			t.Run(mode+"/"+f.name, func(t *testing.T) {
				r := newRig(t, nil)
				if mode == "unlocked" {
					r.unlock()
				}
				bare := r.say("STOP")
				resume := regexp.MustCompile(`RESUME ([0-9]{6})`).FindStringSubmatch(r.say("resume"))[1]
				if mode == "challenged" {
					r.ch.codes.st.Challenged = true
				}
				if mode != "unlocked" {
					r.say("hold this one") // a held message the STOP must leave alone
				}
				c := r.totp()
				c2 := r.totp()
				text := f.text(c, c2)
				r.eng.mu.Lock()
				r.eng.stopped = false // running again, so this STOP has work to do
				r.eng.mu.Unlock()
				gen, sent := r.ch.stops.Load(), len(r.agent.got())
				st := r.ch.codes.st
				wrong, held := len(st.Wrong), r.ch.held
				got := r.say(text)
				if got != bare || !r.eng.Stopped() {
					t.Fatalf("%q: %q (bare STOP: %q), stopped %v", text, got, bare, r.eng.Stopped())
				}
				for _, code := range []string{c, c2, c[:5]} {
					if strings.Contains(got, code) {
						t.Fatalf("%q: the reply echoes a code: %q", text, got)
					}
				}
				if r.ch.stops.Load() != gen+1 {
					t.Fatalf("%q was not counted as a STOP", text)
				}
				now := r.ch.codes.st
				if len(r.agent.got()) != sent || len(now.Wrong) != wrong || !now.UnlockedUntil.Equal(st.UnlockedUntil) ||
					now.LastStep != st.LastStep || now.Challenged != st.Challenged || r.ch.held != held {
					t.Fatalf("%q: a code was checked or passed on: agent %v, wrong %d->%d, unlocked until %v->%v, step %d->%d, challenged %v->%v, held changed %v",
						text, r.agent.got(), wrong, len(now.Wrong), st.UnlockedUntil, now.UnlockedUntil,
						st.LastStep, now.LastStep, st.Challenged, now.Challenged, r.ch.held != held)
				}
				// Challenge mode ignores codes outright, so leave it to
				// show the RESUME code itself is void.
				r.ch.codes.st.Challenged = false
				if got := r.say("RESUME " + resume); !strings.HasPrefix(got, "No valid code") || !r.eng.Stopped() {
					t.Fatalf("%q: a RESUME code from before it lifted it: %q", text, got)
				}
			})
		}
	}
}

// TestStopFormKeepsWholeMessageRule: STOP with any word that is not
// code-like is not a control word (CH-11), so it stays chat or is held,
// and a reaction quoting a code is never STOP (SEC-stop-forms).
func TestStopFormKeepsWholeMessageRule(t *testing.T) {
	for text, want := range map[string]bool{
		"STOP":                       true,
		"  stop!  ":                  true,
		"STOP STOP":                  true,
		"12 STOP 34":                 true,
		"STOP A1":                    true,
		"STOP J10":                   true,
		"stop the newsletter":        false,
		"please stop 123456":         false,
		"STOP 12 now":                false,
		"STOP K3":                    false,
		"STOP A11":                   false,
		"STOP A0":                    false,
		"STOP H03":                   false,
		"STOPS 123456":               false,
		"STOP1 123456":               true,
		"123456STOP":                 true,
		"STOP £":                     true,
		"STOPS1":                     false,
		"XSTOP 123456":               false,
		"STOPK3":                     false,
		"STOP GBP 123456":            false,
		"STOP £ now":                 false,
		"stop" + "\u00a3" + "50 now": false,
		"123456":                     false,
		"":                           false,
		"stop the 3 jobs":            false,
		`Liked "STOP 123456"`:        false,
		"STOP flight AB482913":       false,
		fullWidth("STOP now"):        false,
		fullWidth("STOP") + " ＨＯＭＥ":  false,
	} {
		if got := stopForm(text); got != want {
			t.Errorf("stopForm(%q) = %v, want %v", text, got, want)
		}
	}
}

// TestStopFormChatStillReachesTheAgent: unlocked, STOP followed by other
// words is chat and reaches the agent as sent, with nothing stopped
// (CH-11 holds alongside SEC-stop-forms).
func TestStopFormChatStillReachesTheAgent(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	gen := r.ch.stops.Load()
	r.say("stop the newsletter")
	if r.eng.Stopped() || r.ch.stops.Load() != gen {
		t.Fatal("chat that starts with stop stopped the box")
	}
	if got := r.agent.got(); len(got) != 1 || !strings.Contains(got[0], "stop the newsletter") {
		t.Fatalf("chat did not reach the agent: %v", got)
	}
}

// TestStopFormFromAStrangerIsNothing: a STOP form from any number but the
// owner's is not STOP: nothing stops, nothing is counted in the STOP
// generation and no reply goes out (CH-2 is the owner's word only).
func TestStopFormFromAStrangerIsNothing(t *testing.T) {
	r := newRig(t, nil)
	r.unlock()
	gen := r.ch.stops.Load()
	for _, text := range []string{"STOP", "STOP," + r.totp(), "123456 STOP", "STOP H3", fullWidth("STOP")} {
		if got := r.sayFrom(stranger, text); got != "" || r.eng.Stopped() || r.ch.stops.Load() != gen {
			t.Fatalf("%q from a stranger: reply %q, stopped %v, counted %v", text, got, r.eng.Stopped(), r.ch.stops.Load() != gen)
		}
	}
}

// TestStopFormKeepsEveryOldStop: every message the reader before
// SEC-stop-forms took as STOP (control.Parse of the text with a trailing
// 6-digit code split off) is still a STOP form, so widening the forms
// drops none, including symbols fold expands to letters ("STOP £ 123456").
// Random messages are drawn from STOP's pieces, digits, grid cells,
// separators, currency signs, full-width forms and format characters.
func TestStopFormKeepsEveryOldStop(t *testing.T) {
	old := func(text string) bool {
		rest, _ := splitCode(text)
		return control.Parse(rest).Word == control.WordStop
	}
	parts := []string{"STOP", "stop", "St", "OP", "123456", "1234567", "12", "H3", "j10", "K3",
		" ", ",", "-", ".", "!", "£", "€", "¥", "$", "\u200b", "\u0301", "ＳＴＯＰ", "１２３", "，", "\t", "x"}
	for _, text := range []string{"STOP £ 123456", "STOP €", "£STOP", "STOP ¥¥ 123456", "STOP\u200b", " STOP 123456 "} {
		if !old(text) || !stopForm(text) {
			t.Errorf("%q: old reader %v, stopForm %v", text, old(text), stopForm(text))
		}
	}
	rng := rand.New(rand.NewSource(2475))
	found := 0
	for i := 0; i < 200000; i++ {
		var b strings.Builder
		for n := 1 + rng.Intn(6); n > 0; n-- {
			b.WriteString(parts[rng.Intn(len(parts))])
		}
		text := b.String()
		if old(text) {
			found++
			if !stopForm(text) {
				t.Fatalf("%q was STOP before SEC-stop-forms and is not now", text)
			}
		}
	}
	if found < 1000 {
		t.Fatalf("only %d old STOP messages drawn; the generator is too narrow", found)
	}
}
