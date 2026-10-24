package imapconn

// REQ: KRN-2, CLK-1

import (
	"os/exec"
	"strings"
	"testing"
)

// TestTheConnectionLinksNoCredentialHolder (KRN-2): the connection process
// links nothing that holds or reaches the mail clerk's Secrets, its sealer,
// its kernel socket or the network: not the clerk, its sealed store, its
// process, the kernel, the address policy or SMTP.
func TestTheConnectionLinksNoCredentialHolder(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./clerk/inbox/imapconn", "./clerk/inbox/imapconn/cmd/imapconn")
	cmd.Dir = "../../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	deps := strings.Fields(string(out))
	if len(deps) < 10 {
		t.Fatalf("go list listed %d packages", len(deps))
	}
	const own = "github.com/ghbmrk/agentos/broker/"
	for _, p := range deps {
		switch {
		case p == own+"clerk", strings.HasPrefix(p, own+"clerk/seal"), strings.HasPrefix(p, own+"clerk/run"),
			strings.HasPrefix(p, own+"kernel"), strings.HasPrefix(p, own+"netguard"), p == "net/smtp",
			strings.HasPrefix(p, own+"clerk/inbox/imapsmtp"):
			t.Errorf("the connection process links %s", p)
		}
	}
}
