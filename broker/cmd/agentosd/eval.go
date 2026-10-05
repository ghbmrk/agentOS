package main

import (
	"log"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/replay"
	"github.com/ghbmrk/agentos/broker/vm"
)

// evalConfig is what the change pipeline's wiring (W3) supplies to open the
// evaluator: the pipeline's active tree and probe-to-task lookup, and the
// spare meter that holds evaluation's share (loops L3).
type evalConfig struct {
	Dir    string  // the replay machines' socket directories
	Spec   vm.Spec // image, memory, Argv and Env; replay sets class and label
	Egress string  // the vault process's model socket; empty: offline
	Spare  *meter.Meter
	Active func(ns string) change.Tree
	Task   func(probeID string) (intentID string, ok bool)
}

// openEvaluator opens the change pipeline's evaluator (LOOP-5, CHG-1) in
// agentosd, beside the machine manager and journal it needs, and routes
// replay machines to it (arbitrator on W3a, superseding agentos-eval).
// Replay never calls a model itself (replay R10): a replay machine's
// guest calls are forwarded to the vault process like a live guest's,
// carrying the tree's routing rule, which the vault process applies only
// within the agent machine's grants (egress -eval-from). Without a vault
// socket or spare meter, replay is offline and routing changes are not
// evaluated (replay R2).
func openEvaluator(m *vm.Manager, eng *journal.Engine, services *lateServices, c evalConfig) (*replay.Evaluator, error) {
	cfg := replay.Config{
		Machines:   m,
		Recordings: replay.JournalRecordings{J: eng, Task: c.Task},
		Active:     c.Active,
		Spec:       c.Spec,
		Dir:        c.Dir,
		Logf:       log.Printf,
	}
	if c.Egress != "" && c.Spare != nil {
		cfg.Meter = c.Spare
		cfg.Model = replay.RuleModel(modelroute.Evaluation(modelroute.Config{
			Socket: c.Egress,
			Label:  func(string) string { return "private" },
			Denied: func(machine string, x modelroute.Denial) {
				n := journal.EgressNote{Machine: machine, Adapter: x.Adapter, Operation: x.Operation, Method: x.Method, Status: x.Status, Reason: x.Reason}
				if n.Reason == "" {
					n.Reason = "denied"
				}
				if err := eng.RecordEgress(n); err != nil {
					log.Printf("journal egress denial for %s: %v", machine, err)
				}
			},
			Logf: log.Printf,
		}))
	}
	ev, err := replay.New(cfg)
	if err != nil {
		return nil, err
	}
	services.eval.Store(&svc{ev})
	return ev, nil
}
