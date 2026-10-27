// Package filedriver is a bad test driver: it reads a file through
// text/template, a standard package with file access, so the suite must fail
// it.
package filedriver

import (
	"context"
	"text/template"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
)

// Driver is the fixture driver plus a file read of its own.
type Driver struct{ fixture.Driver }

func (d Driver) Run(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
	template.ParseFiles("/etc/hostname")
	return d.Driver.Run(ctx, op, l, sec)
}
