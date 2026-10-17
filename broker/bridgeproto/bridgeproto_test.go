package bridgeproto

import (
	"errors"
	"testing"
)

// REQ: CH-1

// L3 on #170: the bridge offers an inbound text again only while its
// refusal can pass: a paused line, the rate limit, or a lost connection;
// never a bad text or a second-line one.
func TestOnlyPassableRefusalsAreRetried(t *testing.T) {
	for err, want := range map[error]bool{
		nil: false,
		errors.New("bridgeclient: " + RefusedBad):     false,
		errors.New("bridgeclient: " + RefusedSecond):  false,
		errors.New("bridgeclient: " + RefusedPaused):  true,
		errors.New("bridgeclient: " + RefusedLimited): true,
		errors.New("connection reset"):                true,
	} {
		if got := Retryable(err); got != want {
			t.Errorf("Retryable(%v) = %v, want %v", err, got, want)
		}
	}
}

// L3 on #170 (M6): an inbound text must be valid UTF-8. JSON cannot carry
// invalid UTF-8 over owner.sock, so the check is tested directly.
func TestInboundTextIsValidUTF8(t *testing.T) {
	in := Inbound{Line: LineOwner, From: "+15550000999", Text: "ok"}
	if !in.Valid() {
		t.Fatal("a valid text was refused")
	}
	in.Text = "\xff"
	if in.Valid() {
		t.Fatal("invalid UTF-8 was taken")
	}
}

// REQ: CH-12, CH12-mms-c
// A picture (an MMS notice) is passed with no text: one that claims text
// is refused, so nothing reads a picture as a command.
func TestInboundPictureCarriesNoText(t *testing.T) {
	in := Inbound{Line: LineOwner, From: "+15550000999", Picture: true, ID: "p1"}
	if !in.Valid() {
		t.Fatal("a picture was refused")
	}
	in.Text = "STOP"
	if in.Valid() {
		t.Fatal("a picture with text was taken")
	}
}

// P2-2w d2b: a swapped or unbound state carries the SIM serial the bridge
// sees, so agentosd can record it once the owner confirms it with a code.
// A serial is digits (and a hex pad), normalized before it is sent.
func TestICCIDIsNormalizedAndBounded(t *testing.T) {
	if got := NormICCID(" 8901 2600 0000 0000 0001 f "); got != "89012600000000000001F" {
		t.Fatalf("NormICCID = %q", got)
	}
	for s, want := range map[string]bool{
		"89012600000000000001F":   true,
		"8901":                    true,
		"":                        false,
		"8901 26":                 false,
		"89012600000000000001f":   false,
		"8901-26":                 false,
		"89012600000000000000000": false, // 23: past any ICCID
	} {
		if got := ValidICCID(s); got != want {
			t.Errorf("ValidICCID(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestABoxNumberIsE164(t *testing.T) {
	for _, s := range []string{"+15550000100", "+4915550001", "+1234567"} {
		if !ValidNumber(s) {
			t.Errorf("ValidNumber(%q) = false", s)
		}
	}
	for _, s := range []string{"", "+", "15550000100", "+05550000100", "+123456", "+1234567890123456", "+1555 0000100", "+1555000010a"} {
		if ValidNumber(s) {
			t.Errorf("ValidNumber(%q) = true", s)
		}
	}
}
