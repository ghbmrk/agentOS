//go:build !linux

package pacingfile

// No recovery mutation or unleased fallback on an unsupported platform.
func DiscardDuplicateTemporary(string, [32]byte) error { return ErrStorage }
