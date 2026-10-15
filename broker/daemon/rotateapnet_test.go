package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: REC-4, CH-7, ARC-1

// codeVerifier stands in for the vault process's code check: it takes one
// fixed synthetic code.
type codeVerifier struct{}

func (codeVerifier) VerifyTOTP(code string, after int64, _ bool) (int64, bool, error) {
	step := time.Now().Unix() / 30
	return step, code == "246810" && step > after, nil
}

// #1524: the page's rotated-network op reaches agentosd's own hook
// through the daemon's page socket, for a signed-in session only; the
// daemon does not drop the wiring (lcfg.RotateAPNet).
func TestThePageSocketRotatesTheWiFiNetworkThroughItsHook(t *testing.T) {
	dir := t.TempDir()
	var calls atomic.Int32
	cancel, _ := startWith(t, dir, func(c *Config) {
		c.Auth, c.OwnerState = nil, filepath.Join(dir, "owner.json")
		c.OwnerVerifier = codeVerifier{}
		c.PageSocket = &PageSocket{UID: os.Getuid(), RotateAPNet: func() error { calls.Add(1); return nil }}
	})
	defer cancel()
	sock := filepath.Join(dir, "run", localapi.Socket)
	if r := send(t, sock, localapi.OpRotateAPNet, localapi.Auth{}); r.OK || r.Error != localapi.ErrUnauthorized {
		t.Fatalf("without a session: %+v", r)
	}
	r := send(t, sock, localapi.OpSignIn, localapi.SignIn{Code: "246810"})
	var s localapi.Session
	if !r.OK || json.Unmarshal(r.Result, &s) != nil || s.Token == "" {
		t.Fatalf("sign-in: %+v", r)
	}
	if r := send(t, sock, localapi.OpRotateAPNet, localapi.Auth{Token: s.Token}); !r.OK {
		t.Fatalf("rotate: %+v", r)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("hook ran %d times", n)
	}
}
