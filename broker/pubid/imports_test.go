package pubid

import (
	"os/exec"
	"strings"
	"testing"
)

// REQ: OSS-6

// Unlinkability is structural: the publication identity can reach no
// store that knows the owner (vault, journal, recall, owner state, the
// modem, mail, grants) and makes no network call itself, so nothing about
// the owner can enter its key or its batches (OSS-6).
func TestOSS6PubidReachesNoOwnerStoreOrNetwork(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, p := range strings.Fields(string(out)) {
		if strings.HasPrefix(p, "github.com/ghbmrk/agentos/broker/") && p != "github.com/ghbmrk/agentos/broker/pubid" &&
			p != "github.com/ghbmrk/agentos/broker/durable" { // a stdlib-only leaf (durable.TestLeaf)
			t.Errorf("pubid links %s", p)
		}
		if p == "net" || strings.HasPrefix(p, "net/") || p == "os/exec" || p == "crypto/tls" {
			t.Errorf("pubid links %s", p)
		}
	}
}
