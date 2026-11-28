package inbox

// REQ: VRB-2

// A mail whose Content-Type carries a bad parameter cannot be read by the
// wording net, so it is an alert: never trashed or unsubscribed unread
// (#6300, #6416, ASSUMPTIONS.md MUT-pin-inbox-badct). The two test names are
// #6300's, kept so go test's run order, which mutgate reads (#6385), is
// unchanged; what they check is #6416's. The rest of #6416's tests are in
// zz_unreadable_test.go, named to sort last for the same reason.

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

// Under a good Content-Type the octet-stream part is not read and the mail is
// no alert; under a bad parameter the whole body is no longer read as text
// (#6300's fallback): the net reports it cannot read the mail, and the mail
// is an alert whatever its parts hold.
func TestBadContentTypeParameterReadsTheWholeBodyAsText(t *testing.T) {
	good := badCTMail(goodCT, badCTBinary)
	if got, ok := mailText([]byte(good)); !ok || strings.Contains(got, "482913") || isAlert([]byte(good), World{}) {
		t.Fatalf("a well-formed mail's octet-stream part was read, or the mail is an alert: %q, %v", got, ok)
	}
	for _, ct := range brokenCTs() {
		raw := badCTMail(ct, "no code here")
		if _, ok := mailText([]byte(raw)); ok {
			t.Errorf("%s: mailText read the mail", ct)
		}
		if !isAlert([]byte(raw), World{}) {
			t.Errorf("%s: a mail the net cannot read is not an alert", ct)
		}
	}
}

// Stopping at the byte bound is no failure: a long base64 text part reads
// to maxTextBytes, plus the newline before the last part read, and the mail
// stays readable.
func TestBadContentTypeReadKeepsTheTextBound(t *testing.T) {
	raw := b64Mail(goodCT, strings.Repeat("garden chairs ", maxTextBytes))
	got, ok := mailText([]byte(raw))
	if !ok || len(got) != maxTextBytes+1 {
		t.Errorf("read %d bytes ok=%v, want %d and true", len(got), ok, maxTextBytes+1)
	}
}
