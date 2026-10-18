package main

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modemlink"
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
	if strings.HasPrefix(text, outagePrefix) && strings.Contains(text, outageMark) {
		return "outage"
	}
	return "other"
}

// outagePrefix and outageMark frame the owner line's recovery notice
// (modemlink's recoveryText, UX U-B1): sent once the line is back after a
// text to the owner could not go, ahead of anything queued. It answers no
// command, so the step passes over it wherever it lands (E16).
const outagePrefix, outageMark = "I couldn't text you from ", " didn't reach you"

// noticeCounts reads what a recovery notice says did not reach the owner,
// in recoveryText's wording: "N text(s)", or "N approval request(s)" and
// optionally "and M other text(s)". texts counts both; ok is false for a
// notice worded otherwise.
var noticeCounts = regexp.MustCompile(`\. ([0-9]+) (texts?|approval requests?)(?: and ([0-9]+) other texts?)? didn't reach you`)

func readNotice(text string) (texts, requests int, ok bool) {
	m := noticeCounts.FindStringSubmatch(text)
	if m == nil {
		return 0, 0, false
	}
	n, _ := strconv.Atoi(m[1])
	if strings.HasPrefix(m[2], "text") {
		return n, 0, true
	}
	other, _ := strconv.Atoi(m[3])
	return n + other, n, true
}

// otherWords are the letter-only words a failure may quote from a text
// replyKind does not know, so a run shows which notice it was.
const otherWords, otherWordLen = 3, 12

// otherLead is up to otherWords leading words of text, each letters only
// (trailing punctuation dropped) and at most otherWordLen long. It stops at
// the first word with a digit or any other mark, so it never quotes a code,
// a number, a time or a token; the carrier is synthetic, but a failure
// still prints no more of a text than names it (E15).
func otherLead(text string) string {
	var out []string
	for _, w := range strings.Fields(text) {
		if len(out) == otherWords {
			break
		}
		w = strings.TrimRight(w, ".,:;!?")
		if w == "" || len(w) > otherWordLen || strings.IndexFunc(w, func(c rune) bool {
			return (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '\''
		}) >= 0 {
			break
		}
		out = append(out, w)
	}
	return strings.Join(out, " ")
}

// kindLead is replyKind's kind, and for other the text's otherLead in
// quotes, as a failure names it.
func kindLead(text string) string {
	k := replyKind(text)
	if k != "other" {
		return k
	}
	return fmt.Sprintf("other (%q)", otherLead(text))
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
	// notices counts the recovery notices passed over, and noticeTexts and
	// noticeRequests what they say did not reach the owner (#2170);
	// unread counts the notices whose counts could not be read.
	notices, noticeTexts, noticeRequests, unread int
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
// comes before the barrier's (CH-1, CH-3). The owner line's recovery
// notice is passed over wherever it lands (E16).
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
			r.reply(m.Text)
		}
	}
	return r
}

func (r *phoneRun) reply(text string) {
	k := replyKind(text)
	switch {
	case k == "outage":
		// Not a reply: the box's account of a text it lost earlier.
		r.notices++
		texts, requests, ok := readNotice(text)
		if !ok {
			r.unread++
		}
		r.noticeTexts += texts
		r.noticeRequests += requests
	case !r.statusSent:
		if k == "help" {
			r.probed = true
			return
		}
		r.err = fmt.Errorf("HELP drew %s", kindLead(text))
	case r.strangerSent:
		if k != "help" || !r.barrierSent {
			r.err = fmt.Errorf("the unpaired number's text drew %s to the paired number", kindLead(text))
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
		r.err = fmt.Errorf("STATUS with a fresh code drew %s, not the unlock", kindLead(text))
	case !r.status && k == "status":
		r.status = true
	default:
		r.err = fmt.Errorf("after the unlock, %s instead of the status reply", kindLead(text))
	}
}

// noticeNote is the step's one line on the notices it passed over: their
// counts only, so the run shows that a text was lost and how many, never
// when or which (E15, E16). It is "" when there was none.
func (r phoneRun) noticeNote() string {
	if r.notices == 0 {
		return ""
	}
	n := fmt.Sprintf("passed-over recovery notices=%d texts=%d requests=%d", r.notices, r.noticeTexts, r.noticeRequests)
	if r.unread > 0 {
		n += fmt.Sprintf(" unread=%d", r.unread)
	}
	return n
}

// lostSendMax bounds the lost sends phone-control notes: the last ones.
const lostSendMax = 5

// lostSendVia bounds the calls a lost-send note names, as modemlink does.
const lostSendVia = 3

// lostSendWord bounds each word of a lost-send note.
const lostSendWord = 40

// missedLine is agentosd's log line for a text the down owner line did not
// carry (modemlink.MissedLog), after the log's own date and time.
var missedLine = regexp.MustCompile(`^(?:[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} )?` +
	regexp.QuoteMeta(modemlink.MissedLog) + ` kind=(\S*)(.*)$`)

// notWord is what a lost-send note's word may not carry: ci_boot.sh takes
// a NOTE of lower-case words and counts only.
var notWord = regexp.MustCompile(`[^a-z0-9]+`)

// lostSendNotes names, from agentosd's journal, the last lostSendMax texts
// the down line did not carry: one note each with its kind and the calls
// that sent it, as words (#2170, E16). modemlink logs no text and no
// time; the journal's time is dropped.
func lostSendNotes(journal string) []string {
	var notes []string
	for _, l := range strings.Split(journal, "\n") {
		m := missedLine.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		kind := m[1]
		if kind != "text" && kind != "request" {
			kind = "other"
		}
		n := "lost-send kind=" + kind
		for i, via := range strings.Split(m[2], " via ")[1:] {
			if i == lostSendVia {
				break
			}
			via = via[strings.LastIndexByte(via, '/')+1:]
			w := strings.Trim(notWord.ReplaceAllString(strings.ToLower(via), "-"), "-")
			if len(w) > lostSendWord {
				w = w[:lostSendWord]
			}
			if w != "" {
				n += " via=" + w
			}
		}
		notes = append(notes, n)
	}
	if len(notes) > lostSendMax {
		notes = notes[len(notes)-lostSendMax:]
	}
	return notes
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
// kinds and counts, and for a text of no known kind only its otherLead.
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
