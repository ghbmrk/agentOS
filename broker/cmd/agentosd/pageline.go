package main

import (
	"errors"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/modemlink"
)

// ownerLine is what the page shows of the modem link (*modemlink.Link).
type ownerLine interface {
	OwnerLineNote() string
	LastOutage() modemlink.Outage
	Others() int
	TimedOut() int
	Dropped() bool
	// SIM is a SIM the owner may adopt: a tag and its last four digits.
	SIM() (tag, ends string)
}

// pageLine is the owner line as the box's Wi-Fi page shows it (P2-2w
// d2a, UX U-B1): the note on the page's status, the rest only to a
// signed-in page (Security D1).
func pageLine(l ownerLine) func() localapi.Line {
	return func() localapi.Line {
		out := localapi.Line{Note: l.OwnerLineNote(), Others: l.Others(), TimedOut: l.TimedOut(), Dropped: l.Dropped()}
		out.SIM, out.SIMEnds = l.SIM()
		if o := l.LastOutage(); !o.To.IsZero() {
			out.Outage = &localapi.Outage{From: o.From, To: o.To, Missed: o.Missed, Requests: o.Requests}
		}
		return out
	}
}

// adoptSIM is the page's adoption of a SIM (P2-2w d2b): the link's stale
// refusal is localsrv's, which does not import the link (ARC-2).
func adoptSIM(adopt func(tag string) error) func(tag string) error {
	return func(tag string) error {
		err := adopt(tag)
		if errors.Is(err, modemlink.ErrStale) {
			return localsrv.ErrStaleSIM
		}
		return err
	}
}
