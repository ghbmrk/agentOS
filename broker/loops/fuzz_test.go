package loops

import "testing"

// Settings requests are parsed from owner texts; any input must parse without
// panicking (soak workflow, CI-SOAK).
func FuzzParseText(f *testing.F) {
	for _, s := range []string{"", "LOOP OFF", "loops on", "SETTINGS"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, msg string) { ParseText(msg) })
}
