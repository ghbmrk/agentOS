package inbox

// REQ: VRB-2

// A multipart mail whose Content-Type carries a bad parameter is read whole
// as text/plain, its non-text parts' bytes included, so alert wording cannot
// hide from the wording net behind a broken header (#6300, ASSUMPTIONS.md
// MUT-pin-inbox-badct). Its own file keeps its imports off the other tests.

import (
	"strings"
	"testing"
)

// badCTMail is a two-part mail: a plain greeting and an octet-stream part
// whose bytes are binary around a login code. ct is the top Content-Type.
func badCTMail(ct, binary string) string {
	return "Subject: Hello\r\nContent-Type: " + ct + "\r\n\r\n" +
		"--XX\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n" +
		"--XX\r\nContent-Type: application/octet-stream\r\n\r\n" + binary + "\r\n" +
		"--XX--\r\n"
}

const badCTBinary = "\x00\xff\xfe\x89PNG\x1a\x00 Your verification code is 482913 \xc3\x28\x00"

func TestBadContentTypeParameterReadsTheWholeBodyAsText(t *testing.T) {
	good := badCTMail("multipart/mixed; boundary=XX", badCTBinary)
	if got := mailText([]byte(good)); strings.Contains(got, "482913") || wordingAlert(got) {
		t.Fatalf("a well-formed mail's octet-stream part was read: %q", got)
	}
	for _, ct := range []string{
		"multipart/mixed; boundary=XX; =broken",
		"multipart/mixed; boundary=XX; b@d=1",
		`multipart/mixed; boundary="XX`,
	} {
		raw := badCTMail(ct, badCTBinary)
		_, body, _ := strings.Cut(raw, "\r\n\r\n")
		got := mailText([]byte(raw))
		if want := "Hello\n" + body; got != want {
			t.Errorf("%s: read %q, want the whole body %q", ct, got, want)
		}
		if !wordingAlert(got) {
			t.Errorf("%s: the code in the binary part did not reach the wording net", ct)
		}
	}
}

// The fallback read keeps maxTextBytes, however long the binary body: the
// subject and the body read fill it, and only the newline between them is
// over.
func TestBadContentTypeReadKeepsTheTextBound(t *testing.T) {
	raw := badCTMail("multipart/mixed; boundary=XX; =broken", strings.Repeat("\x00\xff", maxTextBytes))
	if got := mailText([]byte(raw)); len(got) != maxTextBytes+1 {
		t.Errorf("read %d bytes, want %d", len(got), maxTextBytes+1)
	}
}
