package main

import (
	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/modemlink"
)

// ownerLine is what the page shows of the modem link (*modemlink.Link).
type ownerLine interface {
	OwnerLineNote() string
	LastOutage() modemlink.Outage
	Others() int
	TimedOut() int
	Dropped() bool
}

// pageLine is the owner line as the box's Wi-Fi page shows it (P2-2w
// d2a, UX U-B1): the note on the page's status, the rest only to a
// signed-in page (Security D1).
func pageLine(l ownerLine) func() localapi.Line {
	return func() localapi.Line {
		out := localapi.Line{Note: l.OwnerLineNote(), Others: l.Others(), TimedOut: l.TimedOut(), Dropped: l.Dropped()}
		if o := l.LastOutage(); !o.To.IsZero() {
			out.Outage = &localapi.Outage{From: o.From, To: o.To, Missed: o.Missed, Requests: o.Requests}
		}
		return out
	}
}
