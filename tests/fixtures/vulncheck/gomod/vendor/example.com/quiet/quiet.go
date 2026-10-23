// Package quiet is a planted vendored module whose listed symbol the target never calls.
package quiet

// Safe is called by the target.
func Safe() {}

// Unsafe is the listed symbol; nothing calls it.
func Unsafe() {}
