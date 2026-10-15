package main

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem"
)

// REQ: CH-1, CH-3, CH-11. The phone-control verdict passes only when the
// paired phone got STATUS's reply and the unpaired number got nothing, and
// a failure names reply kinds, never a text.
func TestControlErr(t *testing.T) {
	const secret = "Locked. canary-e2e-7f3a held"
	before := modem.SMS{From: boxNum, To: phoneNum, Text: "Running. earlier"}
	cases := []struct {
		name string
		log  []modem.SMS
		want string // "" passes; otherwise a substring of the error
	}{
		{"status reply", []modem.SMS{
			{From: strangerNum, To: boxNum, Text: "STATUS"},
			{From: phoneNum, To: boxNum, Text: "STATUS 123456"},
			{From: boxNum, To: phoneNum, Text: "Unlocked until 14:05."},
			{From: boxNum, To: phoneNum, Text: "Running. Nothing open."},
		}, ""},
		{"stopped counts as status", []modem.SMS{
			{From: boxNum, To: phoneNum, Text: "Stopped. Reply RESUME to restart."},
		}, ""},
		{"stranger answered", []modem.SMS{
			{From: boxNum, To: strangerNum, Text: "Running."},
			{From: boxNum, To: phoneNum, Text: "Running."},
		}, "unpaired"},
		{"locked only", []modem.SMS{
			{From: boxNum, To: phoneNum, Text: secret},
		}, "got locked"},
		{"no reply", []modem.SMS{
			{From: phoneNum, To: boxNum, Text: "STATUS 123456"},
		}, "no reply"},
		{"status from another number", []modem.SMS{
			{From: strangerNum, To: phoneNum, Text: "Running."},
		}, "no reply"},
	}
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
	if controlErr([]modem.SMS{before}, 0) != nil {
		t.Error("a status reply before the step's start must not count from index 1, but does from 0")
	}
	if controlErr([]modem.SMS{before}, 1) == nil {
		t.Error("a status reply before the step's start counted")
	}
}
