//go:build !linux

package pacingfile

// No recovery mutation or unleased fallback on an unsupported platform.
func DiscardDuplicateTemporary(string, [32]byte, ...*ManifestSettings) error { return ErrStorage }
func discardDuplicateTemporary(string, [32]byte, []uint32) error             { return ErrStorage }
