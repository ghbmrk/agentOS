package owner

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// REQ: CH-14, CH-18

// The hold's bound is owner-set up to MaxHoldSegments, and a hold filled
// at that bound, above the 64 messages the page's lists once carried,
// still runs in one tap (#5187). The page's own cap is checked against
// MaxHoldSegments in broker/localapi (TestMaxInboxCoversTheLargestHold).
func TestHoldAboveSixtyFourRunsInOneTap(t *testing.T) {
	if MaxHoldSegments <= 64 {
		t.Fatalf("MaxHoldSegments %d: no settable hold above 64", MaxHoldSegments)
	}
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.HoldSegments = MaxHoldSegments }
	r.ch = r.open()
	for i := range MaxHoldSegments + 1 {
		r.say(fmt.Sprintf("m%d", i))
	}
	msgs, dropped, _ := r.ch.LocalHeld()
	if len(msgs) != MaxHoldSegments || dropped != 1 {
		t.Fatalf("held %d, dropped %d", len(msgs), dropped)
	}
	var ids []string
	for _, m := range msgs {
		ids = append(ids, m.ID)
	}
	if _, _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal(err)
	}
	n, err := r.ch.LocalRunHeld(ids, ids)
	r.ch.WaitSends()
	if err != nil || n != MaxHoldSegments {
		t.Fatalf("run: %d, %v", n, err)
	}
	if got := r.agent.got(); len(got) != MaxHoldSegments {
		t.Fatalf("agent got %d messages", len(got))
	}
}

// A bound above MaxHoldSegments, or below zero, is refused at New, so no
// settable hold exceeds what one tap can carry.
func TestHoldAboveTheMaximumIsRefused(t *testing.T) {
	cfg := func(n int) Config {
		return Config{Owner: ownerNum, Engine: &fakeEngine{}, Store: &MemStore{}, Secrets: testSecrets, HoldSegments: n}
	}
	if _, err := New(cfg(MaxHoldSegments)); err != nil {
		t.Fatalf("the maximum refused: %v", err)
	}
	for _, n := range []int{MaxHoldSegments + 1, -1} {
		if _, err := New(cfg(n)); err == nil {
			t.Fatalf("HoldSegments %d accepted", n)
		}
	}
}

// A code-generator code anywhere in a locked message, not only at its
// end, is stripped before the message is held, so the page's tap never
// runs it to the agent (CH-18). The digits are synthetic.
func TestHeldCodeMidMessageNeverReachesTheAgent(t *testing.T) {
	r := newRig(t, nil)
	r.edit = func(c *Config) { c.HoldSegments = 4 * DefaultHoldSegments }
	r.ch = r.open()
	code := r.totp()
	cases := []struct{ say, held string }{
		{"pay 123456 now", "pay now"},
		{"pay " + code + " now", "pay now"},
		{"pay " + code + ", then book", "pay, then book"},
		{"pay (" + code + ") now", "pay () now"},
		{"pay ١٢٣٤٥٦ now", "pay now"}, // Arabic-Indic digits
		{"pay １２３４５６ now", "pay now"}, // full-width digits
		{"123456 pay now " + code, "pay now"},
		{"pay 123\u200d456 now", "pay now"}, // zero-width joiner inside
		{"pay 123\u0301456 now", "pay now"}, // combining mark inside
		{"pay 1\ufe0f23456 now", "pay now"}, // variation selector inside
		{"pay 123\u200e456 now", "pay now"}, // bidi mark inside
		{"pay 123\u0903456 now", "pay now"}, // spacing mark (Mc) inside
		{"pay 123\u20dd456 now", "pay now"}, // enclosing mark (Me) inside
		// A transparent character between a word and a code neither keeps
		// the code nor glues it to the word (Security on #5974).
		{"pay\u200b123456 now", "pay now"},
		{"pay 123456\u200bnow", "pay now"},
		{"pay\u2060123456 now", "pay now"},
		{"pay\ufeff123456 now", "pay now"},
		{"pay\u200e123456 now", "pay now"},
		{"pay 123456\u2060now", "pay now"},
	}
	for _, c := range cases {
		r.say(c.say)
	}
	// A number that is not code-shaped is kept as written.
	r.say("room 12, flight AB482913, ref 7654321, 123\u200d4567")
	msgs, _, _ := r.ch.LocalHeld()
	if len(msgs) != len(cases)+1 {
		t.Fatalf("held %+v", msgs)
	}
	var ids []string
	for i, c := range cases {
		ids = append(ids, msgs[i].ID)
		if msgs[i].Text != c.held {
			t.Errorf("%q held as %q, want %q", c.say, msgs[i].Text, c.held)
		}
	}
	last := msgs[len(cases)]
	ids = append(ids, last.ID)
	if last.Text != "room 12, flight AB482913, ref 7654321, 123\u200d4567" {
		t.Errorf("non-code number changed: %q", last.Text)
	}
	if _, _, err := r.ch.LocalSignIn(r.totp()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ch.LocalRunHeld(ids, ids); err != nil {
		t.Fatal(err)
	}
	r.ch.WaitSends()
	got := r.agent.got()
	if len(got) != len(cases)+1 {
		t.Fatalf("agent got %q", got)
	}
	for _, g := range got {
		if strings.Contains(g, code) || strings.Contains(g, "123456") || strings.ContainsFunc(g, foreignNumber) {
			t.Fatalf("a code reached the agent: %q", g)
		}
	}
	if !slices.Contains(got, "room 12, flight AB482913, ref 7654321, 123\u200d4567") {
		t.Fatalf("agent got %q", got)
	}
}

// A locked message that is only codes once they are stripped is not held.
func TestALockedMessageOfOnlyCodesIsNotHeld(t *testing.T) {
	r := newRig(t, nil)
	r.say("123456 654321")
	if msgs, _, _ := r.ch.LocalHeld(); len(msgs) != 0 {
		t.Fatalf("held %+v", msgs)
	}
}
