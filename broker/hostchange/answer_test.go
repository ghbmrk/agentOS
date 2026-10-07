package hostchange

import (
	"os"
	"strings"
	"testing"
)

// REQ: HW-8, ONB-7
func TestHOST1cR2AsksRecoveryPrompt(t *testing.T) {
	for _, msg := range []string{
		"Windows is asking for a BitLocker recovery key",
		"why does it want a recovery key?",
		"help with recovery key prompt",
	} {
		if !AsksRecoveryPrompt(msg) {
			t.Fatalf("should match %q", msg)
		}
	}
	for _, msg := range []string{
		"STATUS",
		"where's my AgentOS card recovery key",
		"hello",
	} {
		if AsksRecoveryPrompt(msg) {
			t.Fatalf("should not match %q", msg)
		}
	}
}

// REQ: HW-8, ONB-7
func TestHOST1cR2AnswerFromGuide(t *testing.T) {
	b, err := os.ReadFile(guidePath)
	if err != nil {
		t.Fatal(err)
	}
	ans := RecoveryPromptAnswer(string(b))
	if ans == "" {
		t.Fatal("empty answer")
	}
	for _, want := range []string{"aka.ms/myrecoverykey", "BitLocker", "IT department",
		"not the recovery key on your AgentOS card"} {
		if !strings.Contains(ans, want) {
			t.Errorf("missing %q", want)
		}
	}
	if AsksRecoveryPrompt("STATUS") {
		t.Fatal("STATUS matched")
	}
}
