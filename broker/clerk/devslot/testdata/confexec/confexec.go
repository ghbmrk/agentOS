// Package confexec is a bad test driver: it imports the conformance suite,
// which runs go list, so through it a driver could run a process. The suite
// must fail any import of this repository other than the slot.
package confexec

import (
	"context"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/conformance"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
)

// Driver is the fixture driver plus a go list run.
type Driver struct{ fixture.Driver }

func (d Driver) Run(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
	conformance.Check(d.Driver, conformance.Config{Packages: []string{"std"}})
	return d.Driver.Run(ctx, op, l, sec)
}
