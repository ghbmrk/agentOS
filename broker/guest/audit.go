package guest

import (
	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
)

// Recorder is the journal's audit entry point.
type Recorder interface {
	RecordEgress(journal.EgressNote) error
}

// EgressJournal is the egress proxy's Auditor: every denial becomes a
// journal record (ADP-10, egress E6). Allowed requests are counted by the
// meter, not journaled one by one.
type EgressJournal struct {
	Journal Recorder
	Logf    func(format string, args ...any)
}

// Egress implements egress.Auditor.
func (j EgressJournal) Egress(ev egress.Event) {
	if ev.Allowed {
		return
	}
	n := journal.EgressNote{Machine: ev.Machine, Adapter: ev.Adapter, Operation: ev.Operation, Method: ev.Method, Status: ev.Status, Reason: ev.Reason}
	if err := j.Journal.RecordEgress(n); err != nil && j.Logf != nil {
		j.Logf("journal egress denial for %s: %v", ev.Machine, err)
	}
}

// SpendNote is the journal record for a meter exhaustion (OP-8): the first
// refused call of each exhaustion, the one the owner is told about.
func SpendNote(e meter.Exhausted) journal.EgressNote {
	reason := "model spend limit reached (" + e.Scope
	if e.Task != "" {
		reason += " " + e.Task
	}
	return journal.EgressNote{Machine: e.Machine, Status: 429, Reason: reason + ")"}
}
