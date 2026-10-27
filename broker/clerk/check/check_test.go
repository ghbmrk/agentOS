package check_test

import (
	"os/exec"
	"strings"
	"testing"
)

// REQ: KRN-2, ARC-2

// The check path links no network code, so agentosd, whose graph holds no
// network client (daemon.TestAgentosdLinksNoInference), can host a clerk
// that checks its own requests (MIG-4-adapters-f2, #3430).
func TestCheckLinksNoNetwork(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, p := range strings.Fields(string(out)) {
		if p == "net" || strings.HasPrefix(p, "net/") || p == "crypto/tls" || p == "github.com/ghbmrk/agentos/broker/clerk" {
			t.Errorf("clerk/check links %s", p)
		}
	}
}
