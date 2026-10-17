package main

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem"
)

// The step's texts and the box's replies, by kind, for building logs.
var (
	probe     = modem.SMS{From: phoneNum, To: boxNum, Text: "HELP"}
	helpReply = modem.SMS{From: boxNum, To: phoneNum, Text: "Commands: STOP pauses all actions."}
	coded     = modem.SMS{From: phoneNum, To: boxNum, Text: "STATUS 123456"}
	unlockR   = modem.SMS{From: boxNum, To: phoneNum, Text: "Unlocked until 14:05."}
	statusR   = modem.SMS{From: boxNum, To: phoneNum, Text: "Running. Nothing open."}
	stranger  = modem.SMS{From: strangerNum, To: boxNum, Text: "STATUS 654321"}
)

func seq(ms ...modem.SMS) []modem.SMS { return ms }

// REQ: CH-1, CH-3, CH-11, CH-14. The phone-control verdict reads the log in
// order: HELP answered, then STATUS with a fresh code drew the unlock and
// then the status reply, then the unpaired number's text drew nothing
// before the barrier HELP's answer and nothing at all to itself. A failure
// names reply kinds, never a text.
func TestControlErr(t *testing.T) {
	const secret = "canary-e2e-7f3a held"
	canary := func(prefix string) modem.SMS { return modem.SMS{From: boxNum, To: phoneNum, Text: prefix + secret} }
	pass := seq(probe, helpReply, coded, unlockR, statusR, stranger, probe, helpReply)
	cases := []struct {
		name string
		log  []modem.SMS
		want string // "" passes; otherwise a substring of the error
	}{
		{"in order", pass, ""},
		{"stopped counts as status", seq(probe, helpReply, coded, unlockR,
			modem.SMS{From: boxNum, To: phoneNum, Text: "Stopped. Reply RESUME to restart."}, stranger, probe, helpReply), ""},
		{"unanswered probes before one answered", seq(probe, probe, probe, helpReply, coded, unlockR, statusR, stranger, probe, helpReply), ""},
		{"a late probe answer between unlock and status", seq(probe, probe, helpReply, coded, unlockR, helpReply, statusR, stranger, probe, helpReply), ""},
		{"stranger answered", append(seq(probe, helpReply, coded, unlockR, statusR, stranger,
			modem.SMS{From: boxNum, To: strangerNum, Text: "Running. " + secret}), probe, helpReply), "went to the unpaired number"},
		{"stranger's text drew a reply to the paired phone", seq(probe, helpReply, coded, unlockR, statusR, stranger,
			canary("Running. "), probe, helpReply), "unpaired number's text drew status"},
		{"status with no unlock first", seq(probe, helpReply, coded, canary("Running. ")), "no unlock first"},
		{"status before unlock", seq(probe, helpReply, coded, statusR, unlockR), "no unlock first"},
		{"already unlocked", seq(probe, helpReply, coded, canary("You are already unlocked until 14:05. ")), "already unlocked"},
		{"locked", seq(probe, helpReply, coded, canary("Locked. ")), "drew locked"},
		{"wrong code", seq(probe, helpReply, coded, canary("Wrong code. ")), "drew wrong-code"},
		{"unlock then other", seq(probe, helpReply, coded, unlockR, canary("Something ")), "after the unlock, other"},
		{"probe drew other", seq(probe, canary("Locked. ")), "HELP drew locked"},
		{"no reply to probes", seq(probe, probe), "after 2 HELP attempt(s)"},
		{"status from another number", seq(probe, helpReply, coded,
			modem.SMS{From: strangerNum, To: phoneNum, Text: "Running."}), "no reply to STATUS"},
		{"unlock alone", seq(probe, helpReply, coded, unlockR), "no status reply"},
		{"stranger never sent", seq(probe, helpReply, coded, unlockR, statusR), "did not text"},
		{"barrier unanswered", seq(probe, helpReply, coded, unlockR, statusR, stranger, probe), "no reply to HELP after"},
		{"help before the barrier was sent", seq(probe, helpReply, coded, unlockR, statusR, stranger, helpReply, probe), "drew help"},
	}
	before := modem.SMS{From: boxNum, To: phoneNum, Text: "Commands: earlier"}
	for _, c := range cases {
		log := append([]modem.SMS{before}, c.log...)
		err := controlErr(log, 1)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		case err != nil && strings.Contains(err.Error(), "canary"):
			t.Errorf("%s: error carries a text: %v", c.name, err)
		}
	}
	// A probe answered before the step's start does not count.
	if controlErr(append(seq(before), pass[2:]...), 0) != nil {
		t.Error("from 0 the earlier help reply should answer the probe")
	}
	if controlErr(append(seq(before), pass[2:]...), 1) == nil {
		t.Error("a help reply before the step's start counted")
	}
}

// REQ: CH-11, HW-10. A text of no known kind is named by its leading
// letter-only words, so a failed run shows which notice it was, and the
// lead stops before any word with a digit or mark: a code, number, time or
// token is never quoted.
func TestOtherLeadQuotesNoCode(t *testing.T) {
	for _, c := range []struct{ text, want string }{
		{"Daily digest: 2 items held.", "Daily digest"},
		{"Your agent is not running.", "Your agent is"},
		{"Codes 123456 ignored", "Codes"},
		{"canary-e2e-7f3a held", ""},
		{"Too many wrong codes", "Too many wrong"},
		{"Supercalifragilistic word", ""},
		{"", ""},
	} {
		if got := otherLead(c.text); got != c.want {
			t.Errorf("otherLead(%q) = %q, want %q", c.text, got, c.want)
		}
	}
	log := seq(probe, modem.SMS{From: boxNum, To: phoneNum, Text: "Daily digest: 482913 canary-e2e-7f3a"})
	err := controlErr(log, 0)
	if err == nil || err.Error() != `HELP drew other ("Daily digest")` {
		t.Fatalf("controlErr = %v", err)
	}
}
