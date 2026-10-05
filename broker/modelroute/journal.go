package modelroute

import (
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Recorder is the journal's audit entry point (journal.Engine).
type Recorder interface {
	RecordEgress(journal.EgressNote) error
}

// Journal returns a Config.Denied that journals each denial the vault
// process reports, from its proxy or its model router, as an egress
// record under the machine the broker forwarded for, coalesced as the
// proxy's own are (egress E6, journal.EgressGate) so a guest looping on a
// refused request cannot fill the journal. A failed write goes to logf.
func Journal(rec Recorder, logf func(format string, args ...any)) func(machine string, d Denial) {
	return journalWith(rec, logf, nil)
}

func journalWith(rec Recorder, logf func(format string, args ...any), now func() time.Time) func(string, Denial) {
	gate := &journal.EgressGate{Now: now}
	return func(machine string, d Denial) {
		n := journal.EgressNote{Machine: machine, Adapter: d.Adapter, Operation: d.Operation, Method: d.Method, Status: d.Status, Reason: d.Reason}
		if n.Reason == "" {
			n.Reason = "denied"
		}
		if !gate.Admit(&n) {
			return
		}
		if err := rec.RecordEgress(n); err != nil && logf != nil {
			logf("journal egress denial for %s: %v", machine, err)
		}
	}
}
