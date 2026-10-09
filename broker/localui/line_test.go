package localui

import (
	"html"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
)

// REQ: CH-7, CH-1

// P2-2w d2a (U-B1, UX-170-1): the last outage says when and what did not
// reach the owner, in the recovery text's words; the bridge's counts each
// say what happened to those texts.
func TestLineTexts(t *testing.T) {
	from, to := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC), time.Date(2026, 10, 5, 10, 30, 0, 0, time.UTC)
	for _, c := range []struct {
		line localapi.Line
		want []string
	}{
		{localapi.Line{}, nil},
		{localapi.Line{Note: "I can't reach my phone modem. Check it's plugged in."}, nil},
		{localapi.Line{Outage: &localapi.Outage{From: from, To: to}},
			[]string{"Last time I couldn't text you: Oct 5 09:00 to Oct 5 10:30. Nothing was missed."}},
		{localapi.Line{Outage: &localapi.Outage{From: from, To: to, Missed: 1}},
			[]string{"Last time I couldn't text you: Oct 5 09:00 to Oct 5 10:30. 1 text didn't reach you."}},
		{localapi.Line{Outage: &localapi.Outage{From: from, To: to, Missed: 5, Requests: 2}, Others: 3, TimedOut: 1, Dropped: true},
			[]string{
				"Last time I couldn't text you: Oct 5 09:00 to Oct 5 10:30. 2 approval requests and 3 other texts didn't reach you; your agent can ask again.",
				"Since I started, 3 texts to my number came from numbers other than yours. I set them aside unread.",
				"Since I started, 1 text to you may not have gone: my phone modem didn't confirm it.",
				"Since I started, some texts to me were dropped because too many came at once.",
			}},
		{localapi.Line{Outage: &localapi.Outage{From: from, To: to, Missed: 1, Requests: 1}, Others: 1, TimedOut: 2},
			[]string{
				"Last time I couldn't text you: Oct 5 09:00 to Oct 5 10:30. 1 approval request didn't reach you; your agent can ask again.",
				"Since I started, 1 text to my number came from a number other than yours. I set it aside unread.",
				"Since I started, 2 texts to you may not have gone: my phone modem didn't confirm them.",
			}},
	} {
		if got := lineTexts(c.line, time.UTC); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%+v:\n got %q\nwant %q", c.line, got, c.want)
		}
	}
}

// The signed-in home page shows the owner line's note and its counts,
// which it gets over the tokened page_line (Security D1); signed out,
// /home is not served at all.
func TestHomeShowsTheOwnerLine(t *testing.T) {
	r := newRig(t)
	r.runSetup()
	r.startChannel(nil)
	line := localapi.Line{
		Note:     "I can't reach my phone modem. Check it's plugged in.",
		Outage:   &localapi.Outage{From: r.clock().Add(-2 * time.Hour), To: r.clock().Add(-time.Hour), Missed: 2, Requests: 1},
		Others:   4,
		TimedOut: 1,
	}
	r.srv.SetOwner(InProcess(localsrv.New(localsrv.Config{Owner: r.ch, Now: r.clock, Line: func() localapi.Line { return line }}).Ops()))
	if p := r.get("/status"); strings.Contains(p, "other than yours") || strings.Contains(p, "didn&#39;t reach you") {
		t.Fatalf("counts before sign-in: %s", p)
	}
	r.post("/unlock", url.Values{"code": {r.code()}})
	p := r.get("/home")
	want := append([]string{line.Note}, lineTexts(line, time.Local)...)
	if len(want) != 4 {
		t.Fatalf("want %q", want)
	}
	for _, s := range want {
		if !strings.Contains(p, html.EscapeString(s)) {
			t.Errorf("home lacks %q:\n%s", s, p)
		}
	}
	// A line that is fine shows nothing about it.
	line = localapi.Line{}
	if p := r.get("/home"); strings.Contains(p, "phone modem") || strings.Contains(p, "Since I started") {
		t.Fatalf("fine line shown: %s", p)
	}
}
