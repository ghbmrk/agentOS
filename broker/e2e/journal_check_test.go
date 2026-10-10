package e2e

// SIM-check over the journeys: each journey's journal is judged by the
// floor predicates when the journey ends.
//
// REQ: OP-3, OP-4, OP-5, CAP-3

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/journal/check"
)

// checkJournal judges eng's journal once the test and its deferred
// shutdowns are done, with every attempt settled or marked unknown.
func checkJournal(t *testing.T, eng *journal.Engine) {
	t.Helper()
	t.Cleanup(func() {
		for _, v := range check.Engine(eng, false) {
			t.Errorf("journal check: %s", v)
		}
	})
}
