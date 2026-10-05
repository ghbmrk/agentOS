package replay

import (
	"github.com/ghbmrk/agentos/broker/journal"
)

// Journal is the part of the intent engine JournalRecordings reads.
type Journal interface {
	Get(id string) (journal.Status, error)
	List() []journal.Status
}

// JournalRecordings reads a probe's recorded effects from the journal: the
// intents of its case's task. Task maps an opaque probe ID to the journal
// intent the case was recorded on; it is the broker's (the change
// pipeline's case store), never the evaluator's. A task is the intents
// sharing that intent's goal ID, or, for intents with none, its origin (the
// guest lineage that ran it). Broker-state intents are never recordings.
type JournalRecordings struct {
	J    Journal
	Task func(probeID string) (intentID string, ok bool)
}

func (r JournalRecordings) Effects(probeID string) ([]journal.Status, error) {
	task, ok := r.Task(probeID)
	if !ok || task == "" {
		return nil, nil // no task (a security fixture): nothing recorded
	}
	t, err := r.J.Get(task)
	if err != nil {
		return nil, err
	}
	var out []journal.Status
	for _, s := range r.J.List() {
		in := s.Intent
		if in.Account == journal.BrokerAccount {
			continue
		}
		same := in.GoalID == t.Intent.GoalID
		if t.Intent.GoalID == "" {
			same = in.GoalID == "" && in.Origin == t.Intent.Origin
		}
		if same {
			out = append(out, s)
		}
	}
	return out, nil
}
