package run

// REQ: KRN-2

import (
	"os/exec"
	"strings"
	"testing"
)

// TestTheMailClerkLinksNoIMAPParser (KRN-2, #2937 gap 2): the mail clerk's
// process, its mailbox and its transport link no go-imap or go-sasl and not
// the connection process that runs them. The IMAP parser runs only there.
func TestTheMailClerkLinksNoIMAPParser(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "./clerk/run", "./clerk/inbox", "./clerk/inbox/imapsmtp")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	if !strings.Contains(string(out), "broker/clerk/inbox/imapsmtp\n") {
		t.Fatalf("go list did not list the transport:\n%s", out)
	}
	for _, p := range strings.Fields(string(out)) {
		if strings.HasPrefix(p, "github.com/emersion/") || strings.HasSuffix(p, "/clerk/inbox/imapconn") {
			t.Errorf("the mail clerk links %s", p)
		}
	}
}
