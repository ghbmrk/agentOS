package owner

import "testing"

// Owner text arrives from a phone number anyone can text, so the reply parser
// must never panic on it (soak workflow, CI-SOAK).
func FuzzParseReply(f *testing.F) {
	for _, s := range []string{"", "YES 123456", "NO a1b2", "UNDO", "STOP 12345678", "yes\t1\n", "Ω 1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, msg string) {
		parseReply(msg)
		trailingCode(msg)
	})
}
