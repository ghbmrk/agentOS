package guest

import (
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/meter"
)

// SpendNote is the journal record for a meter exhaustion (OP-8): the first
// refused call of each exhaustion, the one the owner is told about.
func SpendNote(e meter.Exhausted) journal.EgressNote {
	reason := "model spend limit reached (" + e.Scope
	if e.Task != "" {
		reason += " " + e.Task
	}
	return journal.EgressNote{Machine: e.Machine, Status: 429, Reason: reason + ")"}
}
