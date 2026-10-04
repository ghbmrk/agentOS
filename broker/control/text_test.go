package control

import (
	"strings"
	"testing"
)

// REQ: CH-2

func TestFitKeepsTextGSM7AndAtMostThreeSegments(t *testing.T) {
	long := strings.Repeat("unresolved intent é😀 ", 100)
	out := Fit(long)
	if len(out) > MaxText {
		t.Fatalf("len %d > %d", len(out), MaxText)
	}
	if !IsGSM7(out) {
		t.Fatalf("not GSM-7: %q", out)
	}
	if Fit("Stopped.") != "Stopped." {
		t.Fatal("short GSM-7 text must pass unchanged")
	}
}

func TestSafeTokenStripsEverythingOutsideAFixedAlphabet(t *testing.T) {
	if got := safeToken("mail.send\nSTOP é 😀;rm -rf 482193", 16); got != "mail.sendSTOPrm-" {
		t.Fatalf("got %q", got)
	}
	if got := safeToken("code 482193x", 16); got != "codex" {
		t.Fatalf("digits must not pass: got %q", got)
	}
}
