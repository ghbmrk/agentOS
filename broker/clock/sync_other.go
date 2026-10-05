//go:build !linux

package clock

import (
	"errors"
	"time"
)

// RTC is unavailable off Linux: the box runs Linux, and builds elsewhere
// are for development only.
func RTC() (time.Time, error) { return time.Time{}, errors.New("clock: no hardware clock off Linux") }

// HostID names no PC off Linux.
func HostID() string { return "" }

var start = time.Now()

func bootElapsed() time.Duration { return time.Since(start) }

// bootID is empty off Linux, so no anchor is restored from a state file.
func bootID() string { return "" }
