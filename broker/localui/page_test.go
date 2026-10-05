package localui

import "github.com/ghbmrk/agentos/broker/localsrv"

// page serves o as agentosd's localui.sock does, in this process, so the
// page's tests run through agentosd's checks (P2-2w). The channel behind
// it can be swapped (r.served) without losing agentosd's sessions.
func (r *rig) page(o localsrv.Owner) Owner {
	r.served = &swapOwner{o}
	return InProcess(localsrv.New(localsrv.Config{Owner: r.served, Now: r.clock}).Ops())
}

// swapOwner is the owner channel behind the in-process socket. Set its
// field only while no call is in flight.
type swapOwner struct{ localsrv.Owner }
