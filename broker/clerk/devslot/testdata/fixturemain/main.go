// Command fixturemain is the fixture driver as a driver binary: the whole
// main a private driver repository writes. Test code, never in an image.
package main

import (
	"github.com/ghbmrk/agentos/broker/clerk/devslot/proc"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
)

func main() { proc.Main(fixture.Driver{}) }
