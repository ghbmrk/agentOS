package s8terms

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// REQ: CRED-5
func TestS8CodexTermsAllowsBrokerHeld(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	// broker/s8terms -> repo root
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../.."))
	b, err := os.ReadFile(filepath.Join(root, "spikes/S8-codex-terms/RESULT.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "broker-held custody (CRED-5 mode B) is allowed for Codex") {
		t.Fatal("missing custody decision")
	}
	if !strings.Contains(text, "developers.openai.com/codex/auth") {
		t.Fatal("missing primary source link")
	}
	if !strings.Contains(text, "Ruled out (Anthropic terms)") {
		t.Fatal("missing Claude contrast")
	}
}
