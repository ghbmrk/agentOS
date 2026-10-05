//go:build !linux

package clock

// Synced is false off Linux: the box runs Linux, and builds elsewhere are
// for development only.
func Synced() (bool, error) { return false, nil }
