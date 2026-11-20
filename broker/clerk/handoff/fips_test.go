package handoff

// REQ: BAK-1

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Where X25519 is refused (Go's FIPS 140-only mode), the package fails at
// load rather than check recipients with no low-order probe (#6287).
func TestNoX25519FailsAtLoad(t *testing.T) {
	if os.Getenv("AGENTOS_HANDOFF_FIPS_CHILD") == "1" {
		return // reached only if the package loaded
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestNoX25519FailsAtLoad$", "-test.count=1")
	cmd.Env = append(os.Environ(), "AGENTOS_HANDOFF_FIPS_CHILD=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "X25519 is not allowed") {
		t.Fatalf("the package loaded without X25519: %v\n%s", err, out)
	}
}
