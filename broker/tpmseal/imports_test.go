package tpmseal_test

import (
	"os/exec"
	"strings"
	"testing"
)

// REQ: ARC-1, ARC-2

// Only the vault process talks to the TPM: it alone holds the vault the
// sealed key opens (vault V2). No other broker binary links this package.
func TestOnlyTheVaultProcessLinksTPMSeal(t *testing.T) {
	out, err := exec.Command("go", "list", "-C", "..", "-f", "{{.ImportPath}} {{join .Deps \" \"}}", "./cmd/...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	const self = "github.com/ghbmrk/agentos/broker/tpmseal"
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		for _, dep := range f[1:] {
			if dep == self && f[0] != "github.com/ghbmrk/agentos/broker/cmd/agentos-egress" {
				t.Errorf("%s links the TPM seal", f[0])
			}
		}
	}
}
