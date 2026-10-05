package localui

import (
	"os/exec"
	"strings"
	"testing"
)

// REQ: ARC-2, CRED-8

// The QR decoder parses untrusted photos from the Wi-Fi, so only the local
// UI's own process links it: neither agentosd (ARC-2) nor the vault
// process may contain gozxing, its x/text and x/xerrors (the standard
// library's own vendor/golang.org/x/text copy is not ours), or this
// package (#50 security C2, L15).
func TestDaemonAndVaultProcessLinkNoScanner(t *testing.T) {
	for _, cmd := range []string{"../cmd/agentosd", "../cmd/agentos-egress"} {
		out, err := exec.Command("go", "list", "-deps", cmd).CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", cmd, err, out)
		}
		for _, p := range strings.Fields(string(out)) {
			if strings.Contains(p, "gozxing") || strings.HasSuffix(p, "/broker/localui") || strings.HasPrefix(p, "golang.org/x/text") || strings.HasPrefix(p, "golang.org/x/xerrors") {
				t.Errorf("%s links %s", cmd, p)
			}
		}
	}
}
