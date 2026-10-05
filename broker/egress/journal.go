package egress

import "github.com/ghbmrk/agentos/broker/journal"

// Recorder is the journal's audit entry point (journal.Engine).
type Recorder interface {
	RecordEgress(journal.EgressNote) error
}

// JournalAuditor is the Auditor the broker uses: every denial becomes a
// journal record (ADP-10, E6). Allowed requests are counted by the OP-8
// meter, not journaled one by one. A failed journal write is reported to
// Logf; the request was already denied.
type JournalAuditor struct {
	Journal Recorder
	Logf    func(format string, args ...any)
}

// Egress implements Auditor.
func (j JournalAuditor) Egress(ev Event) {
	if ev.Allowed {
		return
	}
	n := journal.EgressNote{Machine: ev.Machine, Adapter: ev.Adapter, Operation: ev.Operation, Method: ev.Method, Status: ev.Status, Reason: ev.Reason}
	if err := j.Journal.RecordEgress(n); err != nil && j.Logf != nil {
		j.Logf("journal egress denial for %s: %v", ev.Machine, err)
	}
}
