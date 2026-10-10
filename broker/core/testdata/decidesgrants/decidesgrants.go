// Package decidesgrants is the SIM-core interface fixture: a package
// outside the core that never names grants, yet declares an interface the
// grants gate satisfies through a write path. Wiring passing the gate here
// would let it answer the owner's question itself.
package decidesgrants

import "github.com/ghbmrk/agentos/broker/owner"

type decider interface {
	Decide(d owner.Decision)
}

// Answer decides through whatever the wiring passed in.
func Answer(x decider, d owner.Decision) {
	x.Decide(d)
}
