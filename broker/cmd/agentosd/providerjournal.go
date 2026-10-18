package main

import (
	"fmt"
	"log"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/provagent"
)

// unattributed is the machine a provider run with no caller is journaled
// under.
const unattributed = "unattributed"

// egressRecorder is the engine journal's egress record (journal.Engine).
type egressRecorder interface {
	RecordEgress(journal.EgressNote) error
}

// providerJournal is the OP-8 metering of provider runs (CAP-11-plan-fu1):
// each admitted run is one journal entry of provagent.Event's metadata,
// its machine, outcome and wall time. A plan run is not charged to the
// spend meter: OP-8 meters it as runs, wall time and plan quota with zero
// spend, bounded by RES-2 and the pool's reserve (RES-5). With no rec, entries
// go to the log.
type providerJournal struct{ rec egressRecorder }

// journalProviderRuns wires r's Journal to the engine journal rec.
func journalProviderRuns(r *provagent.Runner, rec egressRecorder) {
	r.Journal = providerJournal{rec: rec}.journal
}

func (p providerJournal) journal(e provagent.Event) {
	m := e.Machine
	if m == "" {
		m = unattributed
	}
	n := journal.EgressNote{Machine: m, Adapter: "provider-" + e.Provider, Operation: e.TaskClass,
		Reason: fmt.Sprintf("provider run %s: %d result bytes in %s", e.Outcome, e.ResultBytes, e.Elapsed.Round(time.Second))}
	if p.rec == nil {
		log.Printf("provider run (journal unwired): %s %s %s: %s", n.Machine, n.Adapter, n.Operation, n.Reason)
		return
	}
	if err := p.rec.RecordEgress(n); err != nil {
		log.Printf("journal provider run for %s: %v", m, err)
	}
}
