// Package latehang is a planted fuzz target for loop7's late-stall test
// (P3-4b-3h-r1): its decoder hangs on its first call a second after its
// worker process's first call, so the worker has returned batches and
// the engine's exec count has moved past the baseline before the worker
// stops. The engine still stops at -test.fuzztime, prints PASS and exits
// 0 with no input stored.
package latehang

import (
	"testing"
	"time"
)

// first is when this worker process's decoder first ran: package state,
// not an input, so the hang is no input the engine could store. A
// second is ten of the worker's 100 ms batches on any machine.
var first time.Time

func FuzzLateHang(f *testing.F) {
	f.Add([]byte("a"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if first.IsZero() {
			first = time.Now()
		}
		if time.Since(first) > time.Second {
			for {
			}
		}
	})
}
