//go:build !linux

package clock

import "time"

// Synced is false off Linux: the box runs Linux, and builds elsewhere are
// for development only.
func Synced() (bool, error) { return false, nil }

var start = time.Now()

func bootElapsed() time.Duration { return time.Since(start) }

// bootID is empty off Linux, so no anchor is restored from a state file.
func bootID() string { return "" }
