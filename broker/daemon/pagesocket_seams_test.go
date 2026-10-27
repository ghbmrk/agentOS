package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CH-9

// seamCertifier is a stand-in for agentosd's pageCertify: it signs
// nothing and answers fixed bytes, so the page's reply shows it was reached.
type seamCertifier struct{}

func (seamCertifier) Certify(context.Context, []byte) (leaf, authority []byte, err error) {
	return []byte("leaf"), []byte("authority"), nil
}

// seamPasskeys is a stand-in for agentosd's passkeys; the test never signs
// in, so none of its methods is reached.
type seamPasskeys struct{}

func (seamPasskeys) List(context.Context) (localapi.PasskeyList, error) {
	return localapi.PasskeyList{}, nil
}
func (seamPasskeys) Begin(context.Context, string, []byte) ([]byte, error) { return nil, nil }
func (seamPasskeys) Finish(context.Context, string, []byte, []byte, []byte) error {
	return nil
}
func (seamPasskeys) CutOff(context.Context, string, []byte, []byte, []byte) error {
	return nil
}

// #3381: daemon.Run passes the page socket's kernel seams through to the
// page's server. Dropping Certify leaves the page serving HTTP only, which
// is fail-safe and so silent (CH-9); dropping Passkeys drops the passkey
// ops. Each seam is checked both ways, so neither half passes alone.
func TestThePageSocketPassesItsKernelSeams(t *testing.T) {
	pub := localapi.CertifyArgs{Pub: []byte("page key")}
	t.Run("set", func(t *testing.T) {
		dir := t.TempDir()
		startLocalUI(t, dir, &PageSocket{UID: os.Getuid(), Certify: seamCertifier{}, Passkeys: seamPasskeys{}})
		sock := filepath.Join(dir, "run", localapi.Socket)
		r := send(t, sock, localapi.OpCertify, pub)
		var c localapi.Certified
		if !r.OK || json.Unmarshal(r.Result, &c) != nil || string(c.Leaf) != "leaf" || string(c.Authority) != "authority" {
			t.Fatalf("certify with the kernel's Certify: %+v", r)
		}
		// Served, the passkey op asks for a session; unserved, it is unknown.
		if r := send(t, sock, localapi.OpPasskeys, localapi.Auth{}); r.OK || r.Error != localapi.ErrUnauthorized {
			t.Fatalf("passkeys with Passkeys: %+v", r)
		}
	})
	t.Run("unset", func(t *testing.T) {
		dir := t.TempDir()
		startLocalUI(t, dir, &PageSocket{UID: os.Getuid()})
		sock := filepath.Join(dir, "run", localapi.Socket)
		if r := send(t, sock, localapi.OpCertify, pub); r.OK || r.Error != localapi.ErrNoAuthority {
			t.Fatalf("certify with no Certify: %+v", r)
		}
		if r := send(t, sock, localapi.OpPasskeys, localapi.Auth{}); r.OK || r.Error != "unknown op" {
			t.Fatalf("passkeys with no Passkeys: %+v", r)
		}
	})
}
