package mail

import "testing"

// Mail is hostile input from anyone; parsing it and its undo evidence must
// never panic (soak workflow, CI-SOAK).
func FuzzParse(f *testing.F) {
	f.Add([]byte("From: a@example.com\r\nSubject: hi\r\n\r\nbody"))
	f.Add([]byte("Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n\r\npart\r\n--x--"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		Parse(raw)
		ParseChange(string(raw))
	})
}
