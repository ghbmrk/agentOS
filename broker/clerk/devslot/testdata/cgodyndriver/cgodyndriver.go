// Package cgodyndriver is a bad test driver: //go:cgo_import_dynamic makes
// its binary load a system library at exec, so the suite must fail the
// directive.
package cgodyndriver

import "github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"

// Driver is the fixture driver in a dynamically linked binary.
type Driver struct{ fixture.Driver }

//go:cgo_import_dynamic libc_getpid getpid "libc.so.6"
