package localapi

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/bridgeproto"
)

// REQ: ARC-2, CH-10

// Security L3 on the P2-2w plan: no page op can be an op of another
// socket, so a page that reached another socket could call nothing there
// by a page op's name, and the other way round.
func TestPageOpsAreDisjointFromOtherSockets(t *testing.T) {
	others := []string{"message", "whoami", bridgeproto.OpInbound, bridgeproto.OpOutbox, bridgeproto.OpSent, bridgeproto.OpState}
	seen := map[string]bool{}
	for _, op := range Ops {
		if !strings.HasPrefix(op, "page_") || seen[op] {
			t.Errorf("op %q", op)
		}
		seen[op] = true
		for _, o := range others {
			if op == o || strings.HasPrefix(o, "page_") {
				t.Errorf("op %q against %q", op, o)
			}
		}
	}
	if len(seen) != 14 {
		t.Fatalf("%d ops", len(seen))
	}
}

// Security L9: agentosd links the contract and its server, never the local
// UI or its QR decoder, and neither carries a network client.
func TestTheContractLinksNoUIAndNoNetworkClient(t *testing.T) {
	for _, pkg := range []string{".", "../localsrv"} {
		out, err := exec.Command("go", "list", "-deps", pkg).CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", pkg, err, out)
		}
		for _, p := range strings.Fields(string(out)) {
			if strings.HasSuffix(p, "/broker/localui") || strings.Contains(p, "gozxing") || p == "net/http" || strings.HasSuffix(p, "/broker/vault") {
				t.Errorf("%s links %s", pkg, p)
			}
		}
	}
}
