//go:build !linux

package pacingfile

// No unleased fallback on an unsupported platform.
type ExclusiveStore struct{}

func OpenExclusive(string) (*ExclusiveStore, error) { return nil, ErrStorage }
func (*ExclusiveStore) Load() ([]byte, error)       { return nil, ErrStorage }
func (*ExclusiveStore) Save([]byte) error           { return ErrStorage }
func (*ExclusiveStore) Close() error                { return nil }

func (*ExclusiveStore) PacingHealth() error { return ErrStorage }
