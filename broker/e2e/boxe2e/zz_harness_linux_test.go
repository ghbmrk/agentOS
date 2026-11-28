package main

import (
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modemlink"
)

// REQ: CH-1, CH-3, CH-11, CH-14

// The driver's own plumbing under phone-control: each request carries the
// box's Origin, a transport error is returned as it is, and the answer's
// body is closed once read.

// errNoBox is the transport's error when the box cannot be reached.
type errNoBox struct{}

func (errNoBox) Error() string { return "synthetic: no route to the box" }

type failRT struct{}

func (failRT) RoundTrip(*http.Request) (*http.Response, error) { return nil, errNoBox{} }

type closeBody struct {
	io.Reader
	closed *bool
}

func (b closeBody) Close() error { *b.closed = true; return nil }

type recordRT struct {
	st     int
	origin string
	closed bool
}

func (t *recordRT) RoundTrip(r *http.Request) (*http.Response, error) {
	t.origin = r.Header.Get("Origin")
	return &http.Response{StatusCode: t.st, Header: http.Header{"Location": {"/status"}},
		Body: closeBody{strings.NewReader("<h2>6. Connect AI</h2>"), &t.closed}, Request: r}, nil
}

func TestDriverRequestsCarryTheOriginAndCloseTheAnswer(t *testing.T) {
	rt := &recordRT{st: http.StatusSeeOther}
	d := &driver{phone: &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	st, loc, b, err := d.get("/setup")
	if err != nil || st != http.StatusSeeOther || loc != "/status" || string(b) != "<h2>6. Connect AI</h2>" {
		t.Fatalf("%d %q %q %v", st, loc, b, err)
	}
	if rt.origin != box || !rt.closed {
		t.Fatalf("origin %q, body closed %v", rt.origin, rt.closed)
	}
	d.phone.Transport = failRT{}
	if st, _, _, err := d.get("/setup"); !errors.Is(err, errNoBox{}) || st != 0 {
		t.Fatalf("%d %v, want the transport's error", st, err)
	}
}

// page is /setup at 200 only: a transport error or any other status fails.
func TestPageNeedsA200(t *testing.T) {
	d := &driver{phone: &http.Client{Transport: failRT{}}}
	if _, err := d.page(); !errors.Is(err, errNoBox{}) {
		t.Fatalf("%v, want the transport's error", err)
	}
	d.phone = &http.Client{Transport: &recordRT{st: http.StatusSeeOther},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if b, err := d.page(); err == nil || err.Error() != `GET /setup 303 "/status"` || b != nil {
		t.Fatalf("%q %v, want GET /setup 303", b, err)
	}
	d.phone.Transport = &recordRT{st: http.StatusOK}
	if b, err := d.page(); err != nil || string(b) != "<h2>6. Connect AI</h2>" {
		t.Fatalf("%q %v", b, err)
	}
}

// phone-control fails as setup not finished when /setup cannot be read,
// and names the transport's error.
func TestPhoneControlNamesAnUnreadableSetupPage(t *testing.T) {
	d := &driver{seed: []byte("12345678901234567890"), carrier: modem.NewCarrier(), phone: &http.Client{Transport: failRT{}}}
	if err := d.phoneControl(); !errors.Is(err, errNoBox{}) || !strings.HasPrefix(err.Error(), "setup not finished: GET /setup: ") {
		t.Fatalf("%v, want setup not finished with the transport's error", err)
	}
}

// until's timeout names the limit, and "timed out" when the check gave no
// error of its own.
func TestUntilNamesItsTimeout(t *testing.T) {
	at := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	d := &driver{now: func() time.Time { return at }, sleep: func(t time.Duration) { at = at.Add(t) }}
	if err := d.until(3*time.Second, func() (bool, error) { return false, nil }); err == nil || err.Error() != "after 3s: timed out" {
		t.Fatalf("%v", err)
	}
	if err := d.until(time.Second, func() (bool, error) { return false, errNoBox{} }); !errors.Is(err, errNoBox{}) {
		t.Fatalf("%v", err)
	}
}

// readJournal reads this boot's journal of the units, its last n lines
// only when n is above 0.
func TestReadJournalTakesTheLastNLinesOnlyWhenAsked(t *testing.T) {
	was := output
	defer func() { output = was }()
	var got [][]string
	output = func(name string, args ...string) string {
		got = append(got, append([]string{name}, args...))
		return ""
	}
	readJournal(5, "agentosd.service")
	readJournal(0, "agentosd.service")
	want := [][]string{
		{"journalctl", "-b", "-o", "cat", "--no-pager", "-n", "5", "-u", "agentosd.service"},
		{"journalctl", "-b", "-o", "cat", "--no-pager", "-u", "agentosd.service"},
	}
	if !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Fatalf("%q, want %q", got, want)
	}
}

// heading quotes at most 60 bytes of the step's heading.
func TestHeadingIsCutAt60(t *testing.T) {
	long := strings.Repeat("a", 70)
	if got, want := heading([]byte("<h2>"+long+"</h2>")), `"`+long[:60]+`"`; got != want {
		t.Fatalf("%s, want %s", got, want)
	}
}

// A note made outside a step names no step.
func TestANoteAfterAStepNamesNoStep(t *testing.T) {
	var out strings.Builder
	r := newReport(&out, nil)
	r.step("phone-control", func() error { return nil })
	r.note("x")
	if got := out.String(); got != "agentos-e2e: PASS phone-control\nagentos-e2e: NOTE  x\n" {
		t.Fatalf("%q", got)
	}
}

// redactLog puts each kept line on one line and cuts it to logLineMax.
func TestRedactLogCutsEachLine(t *testing.T) {
	long := strings.Repeat("x", logLineMax+20)
	if got, want := redactLog("a \t b\n"+long, 5), "a b | "+long[:logLineMax]; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
}

func logSMS(from, to, text string) modem.SMS { return modem.SMS{From: from, To: to, Text: text} }

// readPhoneRun: an index past the log reads nothing; the first reply out
// of order ends the read; a non-help reply after the stranger's text is no
// barrier; an unreadable recovery notice is counted as unread.
func TestReadPhoneRunEdges(t *testing.T) {
	log := []modem.SMS{logSMS(phoneNum, boxNum, "HELP"), logSMS(boxNum, phoneNum, "Running."), logSMS(boxNum, phoneNum, "Commands: HELP")}
	if r := readPhoneRun(log, len(log)+3); r != (phoneRun{}) {
		t.Fatalf("past the log: %+v", r)
	}
	r := readPhoneRun(log, 0)
	if r.err == nil || r.err.Error() != "HELP drew status" || r.probed {
		t.Fatalf("out of order: %+v", r)
	}
	log = []modem.SMS{logSMS(phoneNum, boxNum, "HELP"), logSMS(boxNum, phoneNum, "Commands: HELP"),
		logSMS(phoneNum, boxNum, "111111"), logSMS(boxNum, phoneNum, "That code is right."),
		logSMS(phoneNum, boxNum, "STATUS"), logSMS(boxNum, phoneNum, "Locked."),
		logSMS(strangerNum, boxNum, "123456"), logSMS(phoneNum, boxNum, "HELP"), logSMS(boxNum, phoneNum, "Running.")}
	if r := readPhoneRun(log, 0); r.err == nil || r.err.Error() != "the unpaired number's text drew status to the paired number" || r.barrier {
		t.Fatalf("stranger's reply as the barrier: %+v", r)
	}
	r = readPhoneRun([]modem.SMS{logSMS(boxNum, phoneNum, outagePrefix+"x. Some things"+outageMark)}, 0)
	if r.notices != 1 || r.unread != 1 || r.noticeNote() != "passed-over recovery notices=1 texts=0 requests=0 unread=1" {
		t.Fatalf("unread notice: %+v %q", r, r.noticeNote())
	}
	if _, _, ok := readNotice("no counts here"); ok {
		t.Fatal("a notice worded otherwise read as counts")
	}
}

// A lost-send note names at most lostSendVia calls, each by its last path
// element.
func TestLostSendNotesNameThreeCallsByName(t *testing.T) {
	l := modemlink.MissedLog + " kind=text via a/b/modemlink.askTheOwner via c/d.two via e.three via f.four"
	if got := lostSendNotes(l); len(got) != 1 || got[0] != "lost-send kind=text via=modemlink-asktheowner via=d-two via=e-three" {
		t.Fatalf("%q", got)
	}
}
