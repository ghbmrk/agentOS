// Package journalowner is the journal engine as the owner commands drive
// it (control.Engine), until #2783 (c) leaves STOP, RESUME and STATUS to
// the kernel alone and deletes it with the journal (#2778). daemon wires
// it; the grants tests, which run the owner channel over a journal
// engine, share it rather than copy it.
package journalowner

import (
	"context"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/journal"
)

// Engine is control.Engine over a journal engine.
type Engine struct{ *journal.Engine }

// Stop records a STOP and reports it in control's terms: the cancel
// requests counted are those sent to services that take them.
func (e Engine) Stop(ctx context.Context) (control.StopReport, error) {
	rep, err := e.Engine.Stop(ctx)
	n := 0
	for _, c := range rep.Cancels {
		if c.Supported {
			n++
		}
	}
	return control.StopReport{Held: rep.Held, Unresolved: rep.Unresolved, Cancels: n}, err
}

// List is every intent with the phase STATUS counts it in.
func (e Engine) List() []control.Status {
	var out []control.Status
	for _, s := range e.Engine.List() {
		ph := control.Settled
		switch s.State {
		case journal.InFlight, journal.OutcomeUnknown:
			ph = control.Unsettled
		case journal.Authorized, journal.NotApplied:
			ph = control.Held
		case journal.Pending:
			ph = control.Open
		}
		out = append(out, control.Status{ID: s.Intent.ID, Action: s.Intent.Action, Account: s.Intent.Account, Phase: ph})
	}
	return out
}
