package localui

import (
	"context"
	"errors"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/localsrv"
)

// page serves o as agentosd's localui.sock does, in this process, so the
// page's tests run through agentosd's checks (P2-2w). The channel behind
// it can be swapped (r.served) without losing agentosd's sessions.
func (r *rig) page(o localsrv.Owner) Owner {
	r.served = &swapOwner{o}
	return InProcess(localsrv.New(localsrv.Config{Owner: r.served, Now: r.clock,
		Paused:    func() []localapi.PausedGrant { return r.paused.grants },
		AskResume: r.paused.ask}).Ops())
}

// fakePaused stands in for the gate's paused grants (W5a-resume): an ask
// for a listed grant and pause is recorded; any other is refused as the
// daemon refuses it.
type fakePaused struct {
	grants []localapi.PausedGrant
	asked  []string
}

func (f *fakePaused) ask(_ context.Context, id, pause string) (string, error) {
	for _, g := range f.grants {
		if g.ID == id && g.Pause == pause {
			f.asked = append(f.asked, id+"@"+pause)
			return "Asked to resume " + id + ".", nil
		}
	}
	if id == "G9" {
		return "", errors.New("grants: /var/lib/x")
	}
	return "That grant is no longer paused as this page showed it. Reload the page.", nil
}

// swapOwner is the owner channel behind the in-process socket. Set its
// field only while no call is in flight.
type swapOwner struct{ localsrv.Owner }

// pageWith is page with the follow ops wired as c's (OSS-10).
func (r *rig) pageWith(o localsrv.Owner, c localsrv.Config) Owner {
	r.served = &swapOwner{o}
	c.Owner, c.Now = r.served, r.clock
	return InProcess(localsrv.New(c).Ops())
}
