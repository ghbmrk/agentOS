package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modemlink"
)

// REQ: CH-7, CH-1

type fakeLine struct {
	note             string
	last             modemlink.Outage
	others, timedOut int
	dropped          bool
	sim, ends        string
}

func (f fakeLine) OwnerLineNote() string        { return f.note }
func (f fakeLine) LastOutage() modemlink.Outage { return f.last }
func (f fakeLine) Others() int                  { return f.others }
func (f fakeLine) TimedOut() int                { return f.timedOut }
func (f fakeLine) Dropped() bool                { return f.dropped }
func (f fakeLine) SIM() (string, string)        { return f.sim, f.ends }

// P2-2w d2a: the page's line is the modem link's note, last outage and
// counts; before any outage ended there is none to show.
func TestPageLineFromTheModemLink(t *testing.T) {
	from := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	got := pageLine(fakeLine{note: "n", last: modemlink.Outage{From: from, To: from.Add(time.Hour), Missed: 3, Requests: 1}, others: 2, timedOut: 1, dropped: true})()
	want := localapi.Line{Note: "n", Outage: &localapi.Outage{From: from, To: from.Add(time.Hour), Missed: 3, Requests: 1}, Others: 2, TimedOut: 1, Dropped: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if got := pageLine(fakeLine{})(); !reflect.DeepEqual(got, localapi.Line{}) {
		t.Fatalf("no outage yet: %+v", got)
	}
	// The real link satisfies it.
	var _ ownerLine = modemlink.New(modemlink.Config{})
}
