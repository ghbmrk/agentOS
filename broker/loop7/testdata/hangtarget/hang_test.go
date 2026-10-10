// Package hangtarget is a planted fuzz target for loop7's stall test
// (P3-4b-3r-fuzz): its decoder never returns on an input longer than
// three bytes, so a worker hangs while the engine still stops at
// -test.fuzztime, prints PASS and exits 0 with no input stored.
package hangtarget

import "testing"

func FuzzHang(f *testing.F) {
	f.Add([]byte("a"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 3 {
			for {
			}
		}
	})
}
