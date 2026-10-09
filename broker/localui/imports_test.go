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
// package (#50 security C2, L15). The vault process serves the mailbox
// (egress K18), whose IMAP client and message types bring x/text in, so
// there x/text may enter only through those two importers: any other
// importer, the decoder's included, fails.
func TestDaemonAndVaultProcessLinkNoScanner(t *testing.T) {
	textVia := map[string]map[string]bool{
		"../cmd/agentosd": {},
		"../cmd/agentos-egress": {
			"github.com/emersion/go-imap/utf7":      true,
			"github.com/ghbmrk/agentos/broker/mail": true,
		},
	}
	for cmd, via := range textVia {
		out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", cmd).CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", cmd, err, out)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Fields(line)
			p := f[0]
			if strings.Contains(p, "gozxing") || strings.HasSuffix(p, "/broker/localui") || strings.HasPrefix(p, "golang.org/x/xerrors") {
				t.Errorf("%s links %s", cmd, p)
			}
			if strings.HasPrefix(p, "golang.org/x/text") || via[p] {
				continue
			}
			for _, imp := range f[1:] {
				if strings.HasPrefix(imp, "golang.org/x/text") {
					t.Errorf("%s links %s through %s", cmd, imp, p)
				}
			}
		}
	}
}
