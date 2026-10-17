package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/provagent"
)

// unattributed is the machine a provider run with no caller is journaled
// under; such a run is never charged, so it is refused.
const unattributed = "unattributed"

// egressRecorder is the engine journal's egress record (journal.Engine).
type egressRecorder interface {
	RecordEgress(journal.EgressNote) error
}

// providerJournal is the OP-8 path for provider runs (CAP-11-plan-fu1):
// each admitted run is one journal entry of provagent.Event's metadata,
// and one call of zero tokens on the caller machine's meter, the unit
// modelroute's calls use. A broker-held plan run spends plan quota, not
// tokens (RES-5), so the call count is what it costs the machine. With no
// rec, entries go to the log; with no mtr, every run is refused.
type providerJournal struct {
	rec egressRecorder
	mtr *meter.Meter
}

// meterProviderRuns wires r's Journal and Charge to the engine journal rec
// and the spend meter mtr.
func meterProviderRuns(r *provagent.Runner, rec egressRecorder, mtr *meter.Meter) {
	p := providerJournal{rec: rec, mtr: mtr}
	r.Journal, r.Charge = p.journal, p.charge
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

// charge starts one zero-token call for machine. A machine at its cap is
// refused with the meter's ErrExhausted, which the runner answers used-up;
// no machine, no meter, or a meter fault is a failed run (fail closed).
func (p providerJournal) charge(machine string) (func(), error) {
	if machine == "" || p.mtr == nil {
		return nil, &provagent.Refusal{Reason: provagent.Failed}
	}
	c, err := p.mtr.Start(machine, 0, 0)
	if errors.Is(err, meter.ErrExhausted) {
		return nil, err
	}
	if err != nil {
		log.Printf("meter provider run for %s: %v", machine, err)
		return nil, &provagent.Refusal{Reason: provagent.Failed}
	}
	return func() { c.Done(0) }, nil
}
