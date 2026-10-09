package sendrules_test

import (
	"os/exec"
	"strings"
	"testing"
)

// REQ: ADP-12, CRED-1

// L3 SHOULD-1 on #164: the recipient rules and budget are a leaf with no
// network code, and the second-SIM tool and the AT driver link them
// without smsapi's provider client.
func TestTheRulesLinkNoProviderClient(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, dep := range strings.Fields(string(out)) {
		if strings.HasPrefix(dep, "net") || strings.HasPrefix(dep, "github.com/") && dep != "github.com/ghbmrk/agentos/broker/sendrules" {
			t.Errorf("sendrules links %s", dep)
		}
	}
	for _, pkg := range []string{"../modem/secondline", "../modem/at"} {
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", pkg, err, out)
		}
		if strings.Contains(string(out), "github.com/ghbmrk/agentos/broker/smsapi") {
			t.Errorf("%s links smsapi, the provider client", pkg)
		}
	}
	out, _ = exec.Command("go", "list", "-deps", "../modem/secondline").CombinedOutput()
	if !strings.Contains(string(out), "github.com/ghbmrk/agentos/broker/sendrules") {
		t.Error("modem/secondline does not link sendrules; the fence above checks nothing")
	}
}
