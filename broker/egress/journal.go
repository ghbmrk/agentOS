package egress

import (
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// Recorder is the journal's audit entry point (journal.Engine).
type Recorder interface {
	RecordEgress(journal.EgressNote) error
}

// JournalAuditor is the Auditor the broker uses: denials become journal
// records (ADP-10, E6). Allowed requests are counted by the OP-8 meter,
// not journaled one by one. A failed journal write is reported to Logf;
// the request was already denied.
//
// Denials are coalesced so a looping guest cannot fill the journal: per
// machine and reason class (the reason up to any quoted, guest-chosen
// part, so varying a key name does not open a new entry), the first denial
// in a window (default one minute) is journaled at once, the rest are
// counted, and the count rides on the next note for that machine and
// reason (journal.EgressGate).
type JournalAuditor struct {
	Journal Recorder
	Logf    func(format string, args ...any)
	Window  time.Duration    // default 1 minute
	Now     func() time.Time // default time.Now

	once sync.Once
	gate *journal.EgressGate
}

// Egress implements Auditor.
func (j *JournalAuditor) Egress(ev Event) {
	if ev.Allowed {
		return
	}
	n := journal.EgressNote{Machine: ev.Machine, Adapter: ev.Adapter, Operation: ev.Operation, Method: ev.Method, Status: ev.Status, Reason: ev.Reason}
	j.once.Do(func() { j.gate = &journal.EgressGate{Window: j.Window, Now: j.Now} })
	if !j.gate.Admit(&n) {
		return
	}
	if err := j.Journal.RecordEgress(n); err != nil && j.Logf != nil {
		j.Logf("journal egress denial for %s: %v", ev.Machine, err)
	}
}
