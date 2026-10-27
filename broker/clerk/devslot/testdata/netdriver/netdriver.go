// Package netdriver is a bad test driver: it dials the internet itself, so
// the conformance suite's imports check must fail it.
package netdriver

import (
	"context"
	"net"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
)

// Driver is the fixture driver plus a socket of its own.
type Driver struct{ fixture.Driver }

func (d Driver) Run(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
	if c, err := net.Dial("tcp", "192.0.2.1:443"); err == nil {
		c.Close()
	}
	return d.Driver.Run(ctx, op, l, sec)
}
