package accountsock

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CLK-9, CLK-1

// mailOwnerSocket serves the mail process's real owner table on a fresh
// mail host with no account, under this test's uid.
func mailOwnerSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mail")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	sealer, err := clerk.NewAESSealer(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sec, err := run.OpenSecrets(state, sealer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h := run.NewMailHost(ctx, state, sec, run.MailConfig{Sealer: sealer, World: func() inbox.World { return inbox.World{Today: "2026-10-24"} }})
	sock := filepath.Join(dir, "owner.sock")
	ln, err := run.ListenMail(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go run.ServeMail(ln, h, run.MailOwnerSide)
	return sock
}

// #3006: Gmail's frames are the ones the mail process's owner socket
// takes. A registration that did not arrive would read as a sign-in again
// with no account; one that did gives Google's consent address, and a
// paste that is not that sign-in's is refused by the clerk before any
// code is redeemed, all without reaching the network.
func TestGmailSpeaksTheMailProcesssWire(t *testing.T) {
	sock := mailOwnerSocket(t)
	a := Gmail{sock, os.Getuid()}
	ctx := context.Background()
	if _, d, err := a.Begin(ctx, "watch", nil); err != nil || d != clerk.DNoAccount {
		t.Fatalf("again with no account: %q %v", d, err)
	}
	consent, d, err := a.Begin(ctx, "watch", &localapi.AccountRegistration{ID: "synthetic.apps.googleusercontent.com", Secret: "synthetic-secret"})
	u, perr := url.Parse(consent)
	if err != nil || d != "" || perr != nil || u.Host != "accounts.google.com" || u.Query().Get("client_id") != "synthetic.apps.googleusercontent.com" {
		t.Fatalf("first sign-in: %q %q %v", consent, d, err)
	}
	if strings.Contains(consent, "synthetic-secret") {
		t.Fatal("the consent address carries the client secret")
	}
	redirect := u.Query().Get("redirect_uri")
	d, err = a.Finish(ctx, "watch", redirect+"?state=another&code=c")
	if err != nil || d == "" || strings.HasPrefix(d, clerk.DSignedIn) {
		t.Fatalf("another sign-in's paste: %q %v", d, err)
	}
	// The use the confirm screen named is the clerk's to check (#3008).
	consent, _, _ = a.Begin(ctx, "watch", &localapi.AccountRegistration{ID: "synthetic.apps.googleusercontent.com", Secret: "synthetic-secret"})
	u, _ = url.Parse(consent)
	if d, err = a.Finish(ctx, "sort", redirect+"?state="+u.Query().Get("state")+"&code=c"); err != nil || d != clerk.DUse {
		t.Fatalf("another use: %q %v", d, err)
	}
}

// The socket is called only on the mail process's own uid, and an error
// the clerk answers is not passed on.
func TestGmailCallsOnlyTheMailProcess(t *testing.T) {
	sock := mailOwnerSocket(t)
	if _, _, err := (Gmail{sock, os.Getuid() + 1}).Begin(context.Background(), "watch", nil); err != ErrNoAnswer {
		t.Fatalf("called a socket served by another uid: %v", err)
	}
	if _, _, err := (Gmail{sock + ".none", os.Getuid()}).Begin(context.Background(), "watch", nil); err != ErrNoAnswer {
		t.Fatalf("no socket: %v", err)
	}
	var out string
	if err := (Gmail{sock, os.Getuid()}).call(context.Background(), "gmailnone", struct{}{}, &out); err != ErrNoAnswer {
		t.Fatalf("the clerk's own error: %v", err)
	}
}
