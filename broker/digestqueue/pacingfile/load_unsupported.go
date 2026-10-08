//go:build !linux

package pacingfile

// No fallback to an unbounded or symlink-following reader on other platforms.
func (s Store) Load() ([]byte, error) { return nil, ErrStorage }
