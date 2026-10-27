// Package tlsdriver is a bad test driver: it dials out through crypto/tls, a
// standard package that opens a socket, so the suite must fail it.
package tlsdriver

import (
	"context"
	"crypto/tls"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
)

// Driver is the fixture driver plus a TLS connection of its own.
type Driver struct{ fixture.Driver }

func (d Driver) Run(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
	if c, err := tls.Dial("tcp", "192.0.2.1:443", nil); err == nil {
		c.Close()
	}
	return d.Driver.Run(ctx, op, l, sec)
}
