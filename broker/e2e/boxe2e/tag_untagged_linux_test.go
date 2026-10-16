//go:build !agentos_e2e

package main

import (
	"runtime/debug"
	"testing"
)

// REQ: HW-10

// An untagged test run's own binary does not carry the e2e tag, so hasTag
// does not report a tag the build lacks.
func TestUntaggedBinaryLacksE2ETag(t *testing.T) {
	if own, ok := debug.ReadBuildInfo(); ok && hasTag(own, e2eTag) {
		t.Fatal("untagged test binary carries the e2e tag")
	}
}
