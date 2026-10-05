package smsapi_test

import (
	"os/exec"
	"strings"
	"testing"
)

// REQ: CRED-1, ARC-2

// The texting account's provider client runs in the vault process only:
// agentosd links neither this package nor the SIP stack through it, and
// this package links no SIP or SRTP module, so the vault process's fence
// (sipsign's imports test) still holds.
func TestTheTextingClientStaysInTheVaultProcess(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "../cmd/agentosd").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "github.com/ghbmrk/agentos/broker/smsapi") {
		t.Error("agentosd links smsapi: the texting token must stay in the vault process")
	}
	out, err = exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, s := range []string{"github.com/emiago/sipgo", "github.com/pion/", "github.com/ghbmrk/agentos/broker/vault", "github.com/ghbmrk/agentos/broker/modem/"} {
			if strings.HasPrefix(dep, s) {
				t.Errorf("smsapi links %s", dep)
			}
		}
	}
	out, _ = exec.Command("go", "list", "-deps", "../cmd/agentos-egress").CombinedOutput()
	if !strings.Contains(string(out), "github.com/ghbmrk/agentos/broker/smsapi") {
		t.Error("agentos-egress does not link smsapi; the fence above checks nothing")
	}
}
