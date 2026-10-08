//go:build !linux

package pacingfile

// No unleased/pathname fallback on unsupported platforms.
func InspectTemporary(string, [32]byte) (TemporaryReport, error) {
	return TemporaryReport{}, ErrStorage
}
