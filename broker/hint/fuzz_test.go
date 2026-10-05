package hint

import "testing"

// Hint schemas are untrusted input; parsing must never panic (soak workflow,
// CI-SOAK).
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"fields":[{"name":"a","type":"string"}]}`))
	f.Fuzz(func(t *testing.T, b []byte) { Parse(b) })
}
