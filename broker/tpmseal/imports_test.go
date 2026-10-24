package tpmseal_test

import (
	"os/exec"
	"strings"
	"testing"
)

// REQ: ARC-1, ARC-2

// Only the vault process, the unlock step and enrollment talk to the TPM:
// they alone open or make what the sealed key opens (vault V2, STO-2b,
// STO-2c). The kernel links it for the log anchor's counter alone (LOG-2,
// STO-1), over the one connection the unlock step hands it; it never sees
// the store or a sealed blob. No other broker binary links this package.
var linksTPM = map[string]bool{
	"github.com/ghbmrk/agentos/broker/cmd/agentos-egress":        true,
	"github.com/ghbmrk/agentos/broker/cmd/agentos-enroll":        true,
	"github.com/ghbmrk/agentos/broker/cmd/agentos-kernel":        true,
	"github.com/ghbmrk/agentos/broker/cmd/agentos-kernel/anchor": true,
	"github.com/ghbmrk/agentos/broker/cmd/agentos-unlock":        true,
}

func TestOnlyTheVaultProcessLinksTPMSeal(t *testing.T) {
	out, err := exec.Command("go", "list", "-C", "..", "-f", "{{.ImportPath}} {{join .Deps \" \"}}", "./cmd/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	const self = "github.com/ghbmrk/agentos/broker/tpmseal"
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		for _, dep := range f[1:] {
			if dep == self && !linksTPM[f[0]] {
				t.Errorf("%s links the TPM seal", f[0])
			}
		}
	}
}
