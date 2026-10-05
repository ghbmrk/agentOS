package update

import "testing"

// Attestations come from the network; parsing must never panic (soak
// workflow, CI-SOAK).
func FuzzParseAttestation(f *testing.F) {
	f.Add([]byte(`{"payloadType":"x","payload":"","signatures":[]}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) { ParseAttestation(b) })
}
