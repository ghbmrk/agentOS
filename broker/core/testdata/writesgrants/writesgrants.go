// Package writesgrants is the SIM-core fixture: a package outside the core
// that writes grants directly instead of submitting an intent.
package writesgrants

import (
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// Submit is the one way in, so the check passes it.
func Submit(g *grants.Gate, in journal.Intent) (journal.Status, error) {
	return g.Submit(in)
}

// Decide answers the owner's question itself: a write path outside the core.
func Decide(g *grants.Gate, d owner.Decision) {
	g.Decide(d)
}
