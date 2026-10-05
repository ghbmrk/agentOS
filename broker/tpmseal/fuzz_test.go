package tpmseal

import "testing"

// Counter refs and policy keys are read back from disk; corrupt bytes must
// not panic (soak workflow, CI-SOAK).
func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte(`{"index":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseCounterRef(b)
		ParsePolicyKey(b)
	})
}
