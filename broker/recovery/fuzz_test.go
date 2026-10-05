package recovery

import "testing"

// The recovery key is typed by a person; any text must parse without
// panicking (soak workflow, CI-SOAK).
func FuzzParseRecoveryKey(f *testing.F) {
	f.Add("")
	f.Add("AAAA-BBBB-CCCC-DDDD")
	f.Fuzz(func(t *testing.T, s string) { ParseRecoveryKey(s) })
}
