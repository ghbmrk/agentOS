// Package asmdriver is a bad test driver: a Go assembly file can make raw
// system calls with no import at all, so the suite must fail any assembly.
package asmdriver

import "github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"

// Driver is the fixture driver; trap.s stands for a raw system call.
type Driver struct{ fixture.Driver }

func trap() uintptr
