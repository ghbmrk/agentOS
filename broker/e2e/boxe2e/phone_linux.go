package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ghbmrk/agentos/broker/modem"
)

// strangerNum is a number the box was never paired with, from the same
// reserved range as phoneNum and boxNum.
const strangerNum = "+15550000102"

// replyKind names a text from the box by its first words only, so a
// failure can say what came back without printing the text (CH-11's
// fixed reply shapes; broker/owner and broker/control write them).
func replyKind(text string) string {
	for _, k := range []struct{ prefix, kind string }{
		{"Running.", "status"},
		{"Stopped.", "status"},
		{"Unlocked until ", "unlocked"},
		{"You are already unlocked", "unlocked"},
		{"Locked.", "locked"},
		{"Wrong code.", "wrong-code"},
		{"Commands:", "help"},
	} {
		if strings.HasPrefix(text, k.prefix) {
			return k.kind
		}
	}
	return "other"
}

// controlResult reads the carrier's log from index from onward: whether
// the box answered the paired phone's STATUS, the kinds of the other texts
// it sent the phone, and how many texts it sent the stranger.
func controlResult(log []modem.SMS, from int) (status bool, others []string, toStranger int) {
	if from > len(log) {
		from = len(log)
	}
	for _, m := range log[from:] {
		if m.From != boxNum {
			continue
		}
		switch m.To {
		case phoneNum:
			if k := replyKind(m.Text); k == "status" {
				status = true
			} else {
				others = append(others, k)
			}
		case strangerNum:
			toStranger++
		}
	}
	return status, others, toStranger
}

// controlErr is controlResult as the step's verdict: the paired phone got
// its status reply and the stranger got nothing. It names reply kinds and
// counts, never a text.
func controlErr(log []modem.SMS, from int) error {
	status, others, toStranger := controlResult(log, from)
	switch {
	case toStranger > 0:
		return fmt.Errorf("%d text(s) went to an unpaired number", toStranger)
	case !status && len(others) > 0:
		return fmt.Errorf("no status reply to the paired number; got %s", strings.Join(others, ","))
	case !status:
		return errors.New("no reply to the paired number")
	}
	return nil
}
