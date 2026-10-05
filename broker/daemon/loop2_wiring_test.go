package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/grants"
)

// REQ: LOOP-9, ADP-9

// Security L1 on W5a, over the wire: nothing a peer sends on the owner
// socket, whoever it claims to be and whatever fields it adds, makes an
// intent with Loop 2's origin. Only agentosd sets it, in-process (grants
// TestOnlyTheDaemonUsesTheLoop2Origin); the guest plane is covered by guest
// TestAGuestCannotClaimTheLoop2Origin.
func TestTheOwnerSocketCannotClaimTheLoop2Origin(t *testing.T) {
	dir, _ := os.MkdirTemp("", "bk")
	defer os.RemoveAll(dir)
	cancel, d := start(t, dir)
	sock := filepath.Join(dir, "run", OwnerSocket)
	for _, from := range []string{owner, "+15550000002", grants.OriginLoop2} {
		for _, msg := range []string{"STOP", "PAUSE G1", "RESUME"} {
			send(t, sock, "message", map[string]string{"from": from, "text": msg, "origin": grants.OriginLoop2})
		}
	}
	cancel()
	d.Wait()
	b, err := os.ReadFile(filepath.Join(dir, "journal.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"type":"stop"`) {
		t.Fatal("the owner's STOP did not reach the journal; the test proves nothing")
	}
	if strings.Contains(string(b), grants.OriginLoop2) {
		t.Fatal("a message on the owner socket made an intent with Loop 2's origin")
	}
}
