package control

import "testing"

// Control commands are parsed from owner texts; any input must parse without
// panicking (soak workflow, CI-SOAK).
func FuzzParse(f *testing.F) {
	for _, s := range []string{"", "STATUS", "PAUSE", "help me", "STOP all"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, msg string) { Parse(msg) })
}
