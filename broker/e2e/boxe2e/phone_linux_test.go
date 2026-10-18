package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/sockets"
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
	log := seq(probe, modem.SMS{From: boxNum, To: phoneNum, Text: "Too many wrong codes: 482913 canary-e2e-7f3a"})
	err := controlErr(log, 0)
	if err == nil || err.Error() != `HELP drew other ("Too many wrong")` {
		t.Fatalf("controlErr = %v", err)
	}
}

// outageNotice is the text the box's owner line sends when it recovers
// from an outage in which a text to the owner could not go: modemlink's
// own, made by driving a real Link through one.
func outageNotice(t *testing.T) string { t.Helper(); return outageNoticeOf(t, 1, 0) }

// outageNoticeOf is the notice after an outage in which texts plain texts
// and requests approval requests could not go.
func outageNoticeOf(t *testing.T, texts, requests int) string {
	t.Helper()
	at := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); at = at.Add(time.Second); return at }
	l := modemlink.New(modemlink.Config{Owner: phoneNum, Now: now, PollWait: time.Second, Location: time.UTC})
	for i := 0; i < texts+requests; i++ {
		send := l.Send
		if i >= texts {
			send = l.SendRequest
		}
		if err := send(phoneNum, "Daily digest: 482913 canary-e2e-7f3a"); err == nil {
			t.Fatal("a send before the bridge reported the line went")
		}
	}
	ops := l.Ops()
	if _, err := ops[bridgeproto.OpState](context.Background(), sockets.Peer{}, json.RawMessage(`{"owner_line":"ok"}`)); err != nil {
		t.Fatal(err)
	}
	got, err := ops[bridgeproto.OpOutbox](context.Background(), sockets.Peer{}, json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	it, _ := got.(map[string]any)["item"].(bridgeproto.Item)
	if it.To != phoneNum || it.Text == "" {
		t.Fatalf("no recovery text queued: %#v", got)
	}
	return it.Text
}

// REQ: CH-1, CH-11, CH-14. The daily digest answers no command: phone-control
// passes over it wherever it lands, and a text that only mentions it is
// still other (E17).
func TestDigestIsNotAReply(t *testing.T) {
	n := modem.SMS{From: boxNum, To: phoneNum, Text: "Daily digest: Sun 18 Oct; reply STATUS for more."}
	if k := replyKind(n.Text); k != "digest" {
		t.Fatalf("replyKind(digest) = %q, want digest", k)
	}
	passes := [][]modem.SMS{
		seq(n, probe, helpReply, coded, unlockR, statusR, stranger, probe, helpReply),
		seq(probe, n, helpReply, coded, unlockR, statusR, stranger, probe, helpReply),
		seq(probe, helpReply, coded, n, unlockR, statusR, stranger, probe, helpReply),
		seq(probe, helpReply, coded, unlockR, n, statusR, stranger, probe, helpReply),
		seq(probe, helpReply, coded, unlockR, statusR, stranger, probe, n, helpReply),
	}
	for i, log := range passes {
		if err := controlErr(log, 0); err != nil {
			t.Errorf("digest at %d: %v", i, err)
		}
		if r := readPhoneRun(log, 0); r.notices != 0 {
			t.Errorf("digest at %d counted as %d notice(s)", i, r.notices)
		}
	}
	other := modem.SMS{From: boxNum, To: phoneNum, Text: "Your Daily digest: none"}
	if err := controlErr(seq(probe, other), 0); err == nil || !strings.Contains(err.Error(), "HELP drew other") {
		t.Fatalf("a text not led by the digest prefix: %v, want HELP drew other", err)
	}
	if err := controlErr(seq(probe, helpReply, coded, n, statusR), 0); err == nil || !strings.Contains(err.Error(), "no unlock first") {
		t.Fatalf("a digest stood in for the unlock: %v", err)
	}
}

// REQ: CH-1, CH-3, CH-14. The owner line's recovery notice (UX U-B1) is
// the box's account of a text lost while the line was down, as the
// setup-to-agentosd hand-over can lose one (E9, P2-2w c4c r1); it answers
// no command, so wherever it lands in the step it is passed over, and
// every other check still holds. A text that only starts like it is still
// other (G1 #1688: main's image runs failed "HELP drew other").
func TestOutageNoticeIsNotAReply(t *testing.T) {
	n := modem.SMS{From: boxNum, To: phoneNum, Text: outageNotice(t)}
	if k := replyKind(n.Text); k != "outage" {
		t.Fatalf("replyKind(recovery text) = %q, want outage", k)
	}
	passes := [][]modem.SMS{
		seq(n, probe, helpReply, coded, unlockR, statusR, stranger, probe, helpReply),
		seq(probe, n, helpReply, coded, unlockR, statusR, stranger, probe, helpReply),
		seq(probe, helpReply, coded, n, unlockR, statusR, stranger, probe, helpReply),
		seq(probe, helpReply, coded, unlockR, n, statusR, stranger, probe, helpReply),
		seq(probe, helpReply, coded, unlockR, statusR, stranger, n, probe, helpReply),
		seq(probe, helpReply, coded, unlockR, statusR, stranger, probe, n, helpReply),
		seq(probe, helpReply, coded, unlockR, statusR, stranger, probe, helpReply, n),
	}
	for i, log := range passes {
		if err := controlErr(log, 0); err != nil {
			t.Errorf("notice at %d: %v", i, err)
		}
	}
	fails := []struct {
		log  []modem.SMS
		want string
	}{
		{seq(probe, n), "after 1 HELP attempt(s)"},
		{seq(probe, helpReply, coded, n, statusR), "no unlock first"},
		{seq(probe, helpReply, coded, unlockR, statusR, stranger, n, statusR, probe, helpReply), "unpaired number's text drew status"},
		{seq(probe, n, modem.SMS{From: boxNum, To: strangerNum, Text: n.Text}), "went to the unpaired number"},
		{seq(probe, modem.SMS{From: boxNum, To: phoneNum, Text: "I couldn't text you from 12:00 canary-e2e-7f3a"}), `HELP drew other ("I couldn't text")`},
	}
	for _, c := range fails {
		if err := controlErr(c.log, 0); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v, want %q", err, c.want)
		}
	}
}

// REQ: CH-1. Passing over a recovery notice is not silent (G1-1688 f1,
// #2170): the run counts the notices and what each says did not reach the
// owner, texts in all and approval requests among them, read from
// modemlink's own wording; the note carries those counts only, never a
// time or a text, and a run with no notice has none.
func TestPassedOverNoticesAreCounted(t *testing.T) {
	ok := seq(probe, helpReply, coded, unlockR, statusR, stranger, probe, helpReply)
	if n := readPhoneRun(ok, 0).noticeNote(); n != "" {
		t.Fatalf("a run with no notice noted %q", n)
	}
	for _, c := range []struct {
		texts, requests int
		want            string
	}{
		{1, 0, "passed-over recovery notices=1 texts=1 requests=0"},
		{3, 0, "passed-over recovery notices=1 texts=3 requests=0"},
		{0, 1, "passed-over recovery notices=1 texts=1 requests=1"},
		{2, 2, "passed-over recovery notices=1 texts=4 requests=2"},
	} {
		n := modem.SMS{From: boxNum, To: phoneNum, Text: outageNoticeOf(t, c.texts, c.requests)}
		log := seq(probe, n, helpReply, coded, unlockR, statusR, stranger, probe, helpReply)
		r := readPhoneRun(log, 0)
		if err := controlErr(log, 0); err != nil {
			t.Fatal(err)
		}
		if got := r.noticeNote(); got != c.want {
			t.Errorf("%d texts, %d requests: note %q, want %q", c.texts, c.requests, got, c.want)
		}
	}
	a := modem.SMS{From: boxNum, To: phoneNum, Text: outageNoticeOf(t, 1, 0)}
	b := modem.SMS{From: boxNum, To: phoneNum, Text: outageNoticeOf(t, 1, 1)}
	log := seq(a, probe, helpReply, coded, unlockR, b, statusR, stranger, probe, helpReply)
	if got, want := readPhoneRun(log, 0).noticeNote(), "passed-over recovery notices=2 texts=3 requests=1"; got != want {
		t.Errorf("two notices: %q, want %q", got, want)
	}
	// Nothing of the text but its counts: no digit outside a count, no letters of the notice.
	if got := readPhoneRun(log, 0).noticeNote(); strings.ContainsAny(got, ":.;'") || strings.Contains(got, "12") {
		t.Errorf("note quotes the notice: %q", got)
	}
}

// The sends modemlink logged as missed are noted by kind and caller, in
// lower-case words only, the last lostSendMax of them (#2170). The line
// starts the journal's text, after the log's date and time if any.
func TestLostSendsAreNamed(t *testing.T) {
	journal := strings.Join([]string{
		"setup: done",
		modemlink.MissedLog + " kind=text via owner.watchedLine.Send via owner.(*Channel).sendCounted via main.(*forgetter).tell",
		"owner: something else +15550000999",
		modemlink.MissedLog + " kind=request via owner.(*Channel).sendRequest",
		modemlink.MissedLog + " kind=Text via ../../evil;rm -rf",
		modemlink.MissedLog + " kind=text",
		"2026/10/18 12:00:00 " + modemlink.MissedLog + " kind=text via owner.x",
		"owner: quoting " + modemlink.MissedLog + " kind=text via owner.y",
	}, "\n")
	got := strings.Join(lostSendNotes(journal), "|")
	want := "lost-send kind=text via=owner-watchedline-send via=owner-channel-sendcounted via=main-forgetter-tell|" +
		"lost-send kind=request via=owner-channel-sendrequest|" +
		"lost-send kind=other via=evil-rm-rf|" +
		"lost-send kind=text|" +
		"lost-send kind=text via=owner-x"
	if got != want {
		t.Fatalf("notes %q\nwant %q", got, want)
	}
	var many []string
	for i := 0; i < lostSendMax+2; i++ {
		many = append(many, modemlink.MissedLog+fmt.Sprintf(" kind=text via main.f%d", i))
	}
	n := lostSendNotes(strings.Join(many, "\n"))
	if len(n) != lostSendMax || n[len(n)-1] != fmt.Sprintf("lost-send kind=text via=main-f%d", lostSendMax+1) {
		t.Fatalf("notes %q, want the last %d", n, lostSendMax)
	}
	long := lostSendNotes(modemlink.MissedLog + " kind=text via " + strings.Repeat("a", 200))
	if len(long) != 1 || len(long[0]) > 100 {
		t.Fatalf("a long caller noted %q", long)
	}
	if lostSendNotes("") != nil {
		t.Fatal("an empty journal noted a send")
	}
}
