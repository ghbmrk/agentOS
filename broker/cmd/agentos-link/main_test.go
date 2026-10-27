package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/edgelink"
)

// REQ: HW-15, HW-16

func TestTheEdgesBytesNeverMeetRoot(t *testing.T) {
	// Mutant: helloSpec's Credential dropped (the child then parses as
	// root), or its Groups left nil (it keeps the parent's groups).
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, o := helloSpec(config{uid: 984, gid: 985}, f, nil)
	a := o.SysProcAttr
	if a == nil || a.Credential == nil || a.Credential.Uid != 984 || a.Credential.Gid != 985 || a.Credential.Groups == nil || len(a.Credential.Groups) != 0 {
		t.Fatalf("hello reader's credential %+v, want uid 984, gid 985, no groups", a)
	}
	// Mutant: Pdeathsig dropped (the reader outlives a killed parent).
	if a.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("Pdeathsig %v, want SIGKILL", a.Pdeathsig)
	}
	if len(o.ExtraFiles) != 1 || o.ExtraFiles[0] != f {
		t.Fatal("the listener is not the reader's only extra descriptor (3)")
	}
	// Mutant: servedAs's euid check made false.
	if servedAs(0) == nil {
		t.Fatal("served mode ran as root")
	}
	if err := servedAs(984); err != nil {
		t.Fatalf("served mode as the link's uid: %v", err)
	}
	// Mutant: captureAs's check made false.
	if captureAs(984) == nil {
		t.Fatal("the pre-store parent ran as a plain uid, whose capture enrollment refuses")
	}
	if err := captureAs(0); err != nil {
		t.Fatalf("the pre-store parent as root: %v", err)
	}
}

func TestParseTakesOneModeWithItsPeers(t *testing.T) {
	link := []string{"-iface", "link0", "-port", "7443"}
	pre := append(append([]string{}, link...), "-capture", "/run/c/first-edge", "-store", "/var/lib/s/store", "-uid", "984", "-gid", "984")
	served := append(append([]string{}, link...), "-kernel-sock", "/run/k/link.sock", "-kernel-uid", "980", "-consumer-sock", "/run/l/items.sock", "-consumer-uid", "985")
	for _, ok := range [][]string{pre, served, {"-hello-child"}} {
		if _, err := parse(ok); err != nil {
			t.Errorf("parse(%q): %v", ok, err)
		}
	}
	for name, bad := range map[string][]string{
		"neither":          link,
		"both":             append(append([]string{}, pre...), served[4:]...),
		"no interface":     pre[2:],
		"relative capture": {"-iface", "link0", "-port", "7443", "-capture", "c", "-store", "/s", "-uid", "984", "-gid", "984"},
		"root reader":      {"-iface", "link0", "-port", "7443", "-capture", "/c", "-store", "/s", "-uid", "0", "-gid", "984"},
		"no kernel uid":    {"-iface", "link0", "-port", "7443", "-kernel-sock", "/k", "-consumer-sock", "/l", "-consumer-uid", "985"},
		"bad port":         {"-iface", "link0", "-port", "70000", "-kernel-sock", "/k", "-kernel-uid", "980", "-consumer-sock", "/l", "-consumer-uid", "985"},
		"extra argument":   append(append([]string{}, served...), "x"),
	} {
		if _, err := parse(bad); err == nil {
			t.Errorf("%s: parse took %q", name, bad)
		}
	}
}

func TestACaptureRacingAnotherNeverReplacesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "first-edge")
	first, second := capture(t, newEdge(t)), capture(t, newEdge(t))
	if err := linkCapture(path, first); err != nil {
		t.Fatal(err)
	}
	// Past writeCapture's checks, as a second capture racing the first
	// would be. Mutant: linkCapture's os.Link made os.Rename.
	if err := linkCapture(path, second); err != errTaken {
		t.Fatalf("second link: %v, want errTaken", err)
	}
	if b, _ := os.ReadFile(path); !bytes.Equal(b, first) {
		t.Fatal("the racing capture replaced the first")
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".first-edge-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

// slowKernel answers EdgeKey only after a delay once slow is set.
type slowKernel struct {
	*fakeKernel
	slow chan struct{}
}

func (k slowKernel) EdgeKey(e ed25519.PublicKey) (Edge, error) {
	select {
	case <-k.slow:
		time.Sleep(5 * time.Second)
	default:
	}
	return k.fakeKernel.EdgeKey(e)
}

func TestASlowKernelClosesTheConnectionWithinASecond(t *testing.T) {
	c := newCore(t)
	k := slowKernel{c.k, make(chan struct{})}
	c.s.kernel = k
	live := newEdge(t)
	c.k.setLive(live.key())
	lc := live.dial(c.addr, c.pin)
	defer lc.Close()
	lc.Write(frame(t, edgelink.FromEdge, edgelink.Frame{Kind: edgelink.KindDevice, Origin: "lamp", Body: []byte("on")}))
	if _, ok := c.item(3 * time.Second); !ok {
		t.Fatal("the live edge was not served")
	}
	// Mutant: stillLive waits for the answer however long it takes.
	close(k.slow)
	if !closedWithin(lc, time.Second) {
		t.Fatal("a kernel that does not answer kept the edge served past a second")
	}
}
