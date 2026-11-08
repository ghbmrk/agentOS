package main

import (
	"errors"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/heads"
	"github.com/ghbmrk/agentos/broker/enforcer/page"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The page's view of the daemon's own state (#4750, #4751): the alerts
// and the core's channel sub-key, each as the page's interface
// (page/status.go), so the page links neither alert nor heads
// (ASSUMPTIONS ENF-l-17, ENF-l-18).

// pageAlerts is the alert log as the page shows and clears it.
type pageAlerts struct{ a *alert.Alerts }

func (p pageAlerts) Status() page.Status {
	st := p.a.Status()
	out := page.Status{CoreDown: st.CoreDown, Red: st.Colour == alert.Red}
	for _, r := range st.Open {
		out.Open = append(out.Open, page.Alert{ID: r.ID, Text: r.Text, At: r.At, Count: r.Count, Sent: r.Sent,
			Fixed: r.Kind == alert.ChannelPaused, Revoke: r.Kind == alert.HeadFork})
	}
	return out
}

func (p pageAlerts) Resolve(id uint64) error { return p.a.Resolve(id) }

// pageCore is the pinned core's channel sub-key as the page revokes it.
type pageCore struct{ d *Enforcer }

var errRevokeUnsaved = errors.New("the enforcer refuses the core's key until it restarts, but the revocation was not saved: revoke it again")

func (p pageCore) RevokeMsg(owner key.PublicKey) []byte {
	return key.RootMsg(heads.SubKeyRoot(owner, p.d.core))
}

// Revoke is RevokeCore on the pinned key. A revocation the head store
// keeps in force but could not save says so, so the owner taps again: a
// restart may not keep it. A tap answered done is a whole journal line,
// since the store appends nothing after a fragment it could not cut back
// (heads ENF-h-5).
func (p pageCore) Revoke(sig []byte) error {
	err := p.d.RevokeCore(p.d.core, sig)
	switch {
	case err == nil:
		p.d.revokeUnsaved.Store(false)
		p.d.dp.Logf("core: the owner revoked the core's channel key on the page")
	case p.d.heads.Revoked(p.d.core):
		p.d.revokeUnsaved.Store(true)
		p.d.dp.Logf("core: the owner's revocation is in force but not saved: " + err.Error())
		return errRevokeUnsaved
	}
	return err
}

// Revoked is a revocation the head store saved: one in force but not
// saved is offered again, so the owner's next tap saves it.
func (p pageCore) Revoked() bool { return p.d.heads.Revoked(p.d.core) && !p.d.revokeUnsaved.Load() }
