// Package noracedriver is a bad test driver: //go:norace hides its data
// races from the race detector the driver repository's CI runs, so the
// suite must fail the directive.
package noracedriver

import "github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"

// Driver is the fixture driver plus a counter the race detector skips.
type Driver struct{ fixture.Driver }

var n int

//go:norace
func bump() { n++ }
