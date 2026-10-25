//go:build !linux

package kernelsock

// asUID: a per-thread uid exists only on Linux, so nothing is sent.
func asUID(int, func() error) error { return errNoSeat }
