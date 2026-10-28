package proc

// REQ: CLK-1

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/clerkkey"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// keySock is a clerk's key socket for this test's uid, served under root
// with unitOf telling each peer's unit.
func keySock(t *testing.T, root *[clerkkey.Len]byte, unitOf func(int32) (string, error)) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ck")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := filepath.Join(dir, "clerk-mail.key")
	ln, err := sockets.ListenPeers(p, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serveClerkKey(ln, "mail", "agentos-keeper-mail.service", root, unitOf) }()
	t.Cleanup(func() {
		ln.Close()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return p
}

// handed connects as the service manager would and reads what the kernel
// writes before it closes.
func handed(t *testing.T, p string) []byte {
	t.Helper()
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testRoot() *[clerkkey.Len]byte {
	var r [clerkkey.Len]byte
	for i := range r {
		r[i] = byte(0x80 + i)
	}
	return &r
}

// MAIL-keys: the service manager starting the mail clerk's unit gets the
// mail clerk's key, the same at every start, in the form the clerk's main
// reads (clerkkey.Read); a connection from any other unit, or whose unit
// cannot be read, gets nothing. Fails if a process outside the clerk's unit
// could take its key.
func TestTheKeyGoesOnlyToTheClerksUnit(t *testing.T) {
	root := testRoot()
	units := map[int32]string{int32(os.Getpid()): "agentos-keeper-mail.service"}
	var unitErr error
	p := keySock(t, root, func(pid int32) (string, error) { return units[pid], unitErr })
	want, err := clerkkey.Derive(root, "mail")
	if err != nil {
		t.Fatal(err)
	}
	for start := range 2 {
		b := handed(t, p)
		r, w, _ := os.Pipe()
		w.Write(b)
		w.Close()
		got, err := clerkkey.Read(r, "mail")
		if err != nil || got != want {
			t.Fatalf("start %d: the clerk read %+v, %v; want its derived key", start, got, err)
		}
	}
	for name, set := range map[string]func(){
		"another unit":      func() { units[int32(os.Getpid())] = "agentosd.service" },
		"another instance":  func() { units[int32(os.Getpid())] = "agentos-keeper-mail@x.service" },
		"an unreadable one": func() { units[int32(os.Getpid())], unitErr = "agentos-keeper-mail.service", errors.New("gone") },
	} {
		set()
		if b := handed(t, p); len(b) != 0 {
			t.Errorf("%s was handed %d bytes", name, len(b))
		}
	}
}

// The key socket admits uid 0 alone: under any other uid, the clerk's
// among them, a connection is closed unread.
func TestTheKeySocketAdmitsOnlyRoot(t *testing.T) {
	dir, err := os.MkdirTemp("", "ck")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "k")
	ln, err := ListenClerkKey(p)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveClerkKey(ln, "mail", "agentos-keeper-mail.service", testRoot(), func(int32) (string, error) { return "agentos-keeper-mail.service", nil })
	b := handed(t, p)
	if root := os.Geteuid() == 0; root != (len(b) != 0) {
		t.Fatalf("as uid %d the socket handed %d bytes", os.Geteuid(), len(b))
	}
}

// A kernel with no clerk root key, or a clerk with a bad name or unit,
// serves no key.
func TestNoKeyWithoutARootOrAUnit(t *testing.T) {
	for name, c := range map[string]struct {
		clerk, unit string
		root        *[clerkkey.Len]byte
	}{
		"no root":  {"mail", "agentos-keeper-mail.service", &[clerkkey.Len]byte{}},
		"bad name": {"Mail", "agentos-keeper-mail.service", testRoot()},
		"bad unit": {"mail", "agentos-keeper-mail", testRoot()},
	} {
		if err := serveClerkKey(nil, c.clerk, c.unit, c.root, nil); err == nil {
			t.Errorf("%s: served", name)
		}
	}
}

// The unit is the last element of the process's one unified cgroup line.
func TestCgroupUnit(t *testing.T) {
	for in, want := range map[string]string{
		"0::/agentos-keeper.slice/agentos-keeper-mail.service\n":                                "agentos-keeper-mail.service",
		"0::/system.slice/agentos-driver@hue.service\n":                                         "agentos-driver@hue.service",
		"12:pids:/x\n1:name=systemd:/y\n0::/agentos-keeper.slice/agentos-keeper-mail.service\n": "agentos-keeper-mail.service",
	} {
		if got, err := cgroupUnit([]byte(in)); err != nil || got != want {
			t.Errorf("%q: %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "0::/\n", "0::/init.scope\n", "1:name=systemd:/a.service\n", "0::/a.service\n0::/b.service\n", "0::/agentos-keeper.slice/agentos-keeper-mail.service/sub\n"} {
		if got, err := cgroupUnit([]byte(in)); err == nil {
			t.Errorf("%q read as unit %q", in, got)
		}
	}
	if _, err := procUnit(int32(os.Getpid())); err != nil && !errors.Is(err, ErrKeyPeer) {
		t.Errorf("this process's cgroup file: %v", err)
	}
}

// A kernel told to hand clerks their keys, on a hand-off with no clerk
// root key, refuses to start, before its log opens or a socket listens.
func TestRunKernelNeedsTheClerkRootToHandKeys(t *testing.T) {
	dir := t.TempDir()
	cfg := MainConfig{Log: filepath.Join(dir, "log"), KeyDir: filepath.Join(dir, "keys"), BackupDir: filepath.Join(dir, "b"),
		ClerkKeys: map[string]KeyClerk{"mail": {Socket: filepath.Join(dir, "k"), Unit: "agentos-keeper-mail.service"}}}
	err := RunKernel(t.Context(), cfg, handoff.KernelKeys{Head: headPriv}, &kernel.MemAnchor{})
	if err == nil || !strings.Contains(err.Error(), "no clerk root key") {
		t.Fatalf("got %v, want a refusal for the missing clerk root key", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "log")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the log was opened: %v", err)
	}
}
