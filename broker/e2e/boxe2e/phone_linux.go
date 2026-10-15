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
		{"You are already unlocked", "already-unlocked"},
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

// phoneRun is how far phone-control got, read from the carrier's log in
// the order the texts went (E9). The step's texts, in order: the paired
// phone's HELP probes until one is answered; one STATUS with a fresh code;
// once its status reply is in, the stranger's STATUS with a fresh code;
// then the paired phone's HELP, the barrier.
type phoneRun struct {
	probes       int  // HELP texts the paired phone sent before STATUS
	probed       bool // a help reply came before STATUS was sent
	statusSent   bool
	unlocked     bool // the first reply to STATUS was the unlock
	status       bool // and the status reply followed it
	strangerSent bool // the stranger has texted
	barrierSent  bool
	barrier      bool // a help reply came after the stranger's text
	toStranger   int
	// err is the first reply out of order; it ends the step.
	err error
}

// readPhoneRun reads the log from index from onward. Before STATUS, a
// help reply is a probe's answer. After it, help replies are skipped (a
// late answer to an earlier probe) until the stranger has texted, and the
// first other reply must be the unlock and the next the status: so the
// session was locked and the fresh code unlocked it (CH-14). After the
// stranger's text, the first reply to the paired phone must be help: the
// box reads in arrival order, so a reply drawn by the stranger's text
// comes before the barrier's (CH-1, CH-3).
func readPhoneRun(log []modem.SMS, from int) phoneRun {
	var r phoneRun
	if from > len(log) {
		from = len(log)
	}
	for _, m := range log[from:] {
		if r.err != nil {
			break
		}
		switch {
		case m.From == phoneNum && m.To == boxNum:
			switch {
			case r.strangerSent:
				r.barrierSent = true
			case strings.HasPrefix(m.Text, "STATUS "):
				r.statusSent = true
			case !r.statusSent:
				r.probes++
			}
		case m.From == strangerNum && m.To == boxNum:
			r.strangerSent = true
		case m.From == boxNum && m.To == strangerNum:
			r.toStranger++
		case m.From == boxNum && m.To == phoneNum:
			r.reply(replyKind(m.Text))
		}
	}
	return r
}

func (r *phoneRun) reply(k string) {
	switch {
	case !r.statusSent:
		if k == "help" {
			r.probed = true
			return
		}
		r.err = fmt.Errorf("HELP drew %s", k)
	case r.strangerSent:
		if k != "help" || !r.barrierSent {
			r.err = fmt.Errorf("the unpaired number's text drew %s to the paired number", k)
			return
		}
		r.barrier = true
	case k == "help":
		// A late answer to an earlier probe.
	case !r.unlocked && k == "unlocked":
		r.unlocked = true
	case !r.unlocked && k == "status":
		r.err = errors.New("status reply with no unlock first: the session was not locked")
	case !r.unlocked && k == "already-unlocked":
		r.err = errors.New("already unlocked: the code unlocked nothing")
	case !r.unlocked:
		r.err = fmt.Errorf("STATUS with a fresh code drew %s, not the unlock", k)
	case !r.status && k == "status":
		r.status = true
	default:
		r.err = fmt.Errorf("after the unlock, %s instead of the status reply", k)
	}
}

// failed is the verdict so far: an error once the run cannot pass.
func (r phoneRun) failed() error {
	if r.toStranger > 0 {
		return fmt.Errorf("%d text(s) went to the unpaired number", r.toStranger)
	}
	return r.err
}

// controlErr is the step's verdict on the whole log from index from: every
// stage reached in order, and nothing to the stranger. It names reply
// kinds and counts, never a text.
func controlErr(log []modem.SMS, from int) error {
	r := readPhoneRun(log, from)
	if err := r.failed(); err != nil {
		return err
	}
	switch {
	case !r.probed:
		return fmt.Errorf("no reply to the paired number after %d HELP attempt(s)", r.probes)
	case !r.statusSent:
		return errors.New("STATUS was not sent")
	case !r.unlocked:
		return errors.New("no reply to STATUS with a fresh code")
	case !r.status:
		return errors.New("the unlock came with no status reply")
	case !r.strangerSent:
		return errors.New("the unpaired number did not text")
	case !r.barrier:
		return errors.New("no reply to HELP after the unpaired number's text")
	}
	return nil
}
