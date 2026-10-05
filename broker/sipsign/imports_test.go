package sipsign_test

import (
	"os/exec"
	"strings"
	"testing"
)

// REQ: ARC-2, CRED-1

// The SIP and SRTP stacks parse what a provider and third parties send, so
// they stay in the modem bridge's binary (P2-3c, #102 security R5): the
// vault process links this package and not them, and agentosd links
// neither. A binary that newly needs one is a reviewed change here.
func TestTheSIPStackStaysOutOfTheBrokerAndTheVaultProcess(t *testing.T) {
	sipStack := []string{"github.com/emiago/sipgo", "github.com/pion/", "github.com/ghbmrk/agentos/broker/modem/sipline", "github.com/ghbmrk/agentos/broker/modem/sipsim"}
	for _, pkg := range []string{"../sipsign", "../cmd/agentos-egress", "../cmd/agentosd"} {
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", pkg, err, out)
		}
		for _, dep := range strings.Fields(string(out)) {
			for _, s := range sipStack {
				if strings.HasPrefix(dep, s) {
					t.Errorf("%s links %s", pkg, dep)
				}
			}
		}
	}
	// The vault process's digest arithmetic is the one SIP-adjacent module
	// it links (sipsign.Account).
	out, _ := exec.Command("go", "list", "-deps", "../cmd/agentos-egress").CombinedOutput()
	if !strings.Contains(string(out), "github.com/ghbmrk/agentos/broker/sipsign") {
		t.Error("agentos-egress does not link sipsign; the fence above checks nothing")
	}
	out, _ = exec.Command("go", "list", "-deps", "../cmd/agentosd").CombinedOutput()
	if strings.Contains(string(out), "github.com/ghbmrk/agentos/broker/sipsign") {
		t.Error("agentosd links sipsign: the account's password must stay in the vault process")
	}
}
