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
