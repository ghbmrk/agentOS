package daemon

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: CH-7, CH-10, ARC-2

func startLocalUI(t *testing.T, dir string, ui *PageSocket) {
	t.Helper()
	cancel, _ := startWith(t, dir, func(c *Config) {
		c.Auth = nil
		c.OwnerState = filepath.Join(dir, "owner.json")
		c.PageSocket = ui
	})
	t.Cleanup(cancel)
}

// P2-2w a: agentosd serves the page's ops on localui.sock, given to the
// local UI's group (Security L3), and a raw client with the UI's uid and
// no token is refused every op but status and STOP (L1).
func TestTheLocalUISocketServesThePageOps(t *testing.T) {
	dir := t.TempDir()
	gid := os.Getgid()
	startLocalUI(t, dir, &PageSocket{UID: os.Getuid(), GID: &gid, LineNote: func() string { return "note" }})
	sock := filepath.Join(dir, "run", localapi.Socket)
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o660 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	// The owner line's note reaches the page before sign-in (L3 on #184).
	if r := send(t, sock, localapi.OpStatus, struct{}{}); !r.OK || !strings.Contains(string(r.Result), `"line_note":"note"`) {
		t.Fatalf("status: %+v", r)
	}
	for _, op := range []string{localapi.OpLines, localapi.OpRequests, localapi.OpResume, localapi.OpWaiting, localapi.OpAnswer, localapi.OpSignOut} {
		if r := send(t, sock, op, struct{}{}); r.OK || r.Error != localapi.ErrUnauthorized {
			t.Errorf("%s without a token: %+v", op, r)
		}
	}
	if r := send(t, sock, localapi.OpSignIn, localapi.SignIn{Code: "000000"}); !r.OK || !strings.Contains(string(r.Result), `"refusal":"`+localapi.RefusedWrongCode+`"`) {
		t.Fatalf("wrong sign-in: %+v", r)
	}
	// The sockets keep their own ops (Security L3).
	if r := send(t, sock, "message", map[string]string{"from": owner, "text": "STOP"}); r.OK || r.Error != "unknown op" {
		t.Fatalf("message on localui.sock: %+v", r)
	}
	if r := send(t, filepath.Join(dir, "run", OwnerSocket), localapi.OpStop, struct{}{}); r.OK || r.Error != "unknown op" {
		t.Fatalf("page_stop on owner.sock: %+v", r)
	}
	if r := send(t, sock, localapi.OpStop, struct{}{}); !r.OK {
		t.Fatalf("STOP: %+v", r)
	}
	if r := send(t, sock, localapi.OpStatus, struct{}{}); !r.OK || !strings.Contains(string(r.Result), `"stopped":true`) {
		t.Fatalf("status after STOP: %+v", r)
	}
}

// Only the local UI's uid may connect (SO_PEERCRED).
func TestTheLocalUISocketRefusesOtherUIDs(t *testing.T) {
	dir := t.TempDir()
	startLocalUI(t, dir, &PageSocket{UID: os.Getuid() + 1})
	if r := send(t, filepath.Join(dir, "run", localapi.Socket), localapi.OpStatus, struct{}{}); r.OK || r.Error != "peer not allowed" {
		t.Fatalf("another uid: %+v", r)
	}
}

// Off by default; and it needs the owner channel it serves.
func TestTheLocalUISocketIsOptIn(t *testing.T) {
	dir := t.TempDir()
	cancel, _ := start(t, dir)
	defer cancel()
	if _, err := os.Stat(filepath.Join(dir, "run", localapi.Socket)); !os.IsNotExist(err) {
		t.Fatalf("localui.sock without PageSocket: %v", err)
	}
	cfg := Config{JournalPath: filepath.Join(dir, "j2.log"), SocketDir: filepath.Join(dir, "run2"), OwnerNumber: owner,
		ModemUID: os.Getuid(), PageSocket: &PageSocket{UID: os.Getuid()}}
	if _, err := Run(t.Context(), cfg); err == nil {
		t.Fatal("PageSocket without the owner channel ran")
	}
}

// L3 SHOULD on #184: the socket caps its connections, so a compromised
// page cannot exhaust agentosd's file descriptors.
func TestTheLocalUISocketCapsConnections(t *testing.T) {
	dir := t.TempDir()
	startLocalUI(t, dir, &PageSocket{UID: os.Getuid()})
	sock := filepath.Join(dir, "run", localapi.Socket)
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, c)
		if len(held) <= 8 {
			continue
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		if strings.Contains(line, "too many connections") {
			return
		}
		if time.Now().After(deadline) || len(held) > 64 {
			t.Fatalf("%d connections held, last answered %q", len(held), line)
		}
	}
}
