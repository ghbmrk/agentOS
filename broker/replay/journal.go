package replay

import (
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// Journal is the part of the intent engine JournalRecordings reads.
type Journal interface {
	Get(id string) (journal.Status, error)
	List() []journal.Status
}

// JournalRecordings reads a case's recorded effects from the journal: the
// intents of the case's task. A task is the intents sharing the case
// intent's goal ID, or, for intents with none, its origin (the guest
// lineage that ran it). Broker-state intents are never recordings.
type JournalRecordings struct{ J Journal }

func (r JournalRecordings) Effects(c change.Case) ([]journal.Status, error) {
	if c.Task == "" {
		return nil, nil // security fixtures: no recorded effects
	}
	t, err := r.J.Get(c.Task)
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
