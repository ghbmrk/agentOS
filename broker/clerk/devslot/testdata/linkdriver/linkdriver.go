// Package linkdriver is a bad test driver: //go:linkname reaches runtime
// internals past any import list, so the suite must fail the directive.
package linkdriver

import (
	_ "unsafe"

	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
)

// Driver is the fixture driver plus a linked runtime function.
type Driver struct{ fixture.Driver }

//go:linkname nanotime runtime.nanotime
func nanotime() int64
