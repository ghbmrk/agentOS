// Package tagdriver is a bad test driver: its socket is in a file built only
// under a build tag, which a plain go list skips, so the suite must fail it.
package tagdriver

import "github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"

// Driver is the fixture driver; dial.go adds a socket on the box.
type Driver struct{ fixture.Driver }
