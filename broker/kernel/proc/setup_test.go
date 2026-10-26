package proc

// REQ: KEY-4

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// #2905 open point 2: a kernel process started with no anchors serves only
// the setup step, its box key and STATUS, on any socket, until setup logs
// the owner's hardware keys; then every call is served again.
// setupOnly serves a fresh kernel, which has no anchors yet, on both sides.
func setupOnly(t *testing.T) (Owner, Meter) {
	t.Helper()
	h, err := OpenKernel(KernelConfig{
		Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: headPub, Sign: headPriv,
	}, time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	conns := map[string]Conn{}
	for _, side := range []Side{OwnerSide, MeterSide} {
		path := filepath.Join(shortDir(t), side.name+".sock")
		ln, err := ListenKernel(path, os.Getuid())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go ServeKernel(ln, h, side, func() int64 { return time.Now().UnixMilli() })
		conns[side.name] = Conn{Socket: path, UID: os.Getuid(), Timeout: 10 * time.Second}
	}
	return Owner{conns["owner"]}, Meter{conns["meter"]}
}

func TestASetupOnlyKernelServesOnlySetup(t *testing.T) {
	o, m := setupOnly(t)
	if _, err := o.Status(); err != nil {
		t.Fatalf("STATUS before setup: %v", err)
	}
	for name, err := range map[string]error{
		"stop": o.Stop(), "resume": o.Resume(0), "readpool": m.ReadPool(0, "codex", 1, 2),
	} {
		if !errors.Is(err, ErrSetupOnly) {
			t.Errorf("%s before setup: got %v, want ErrSetupOnly", name, err)
		}
	}
	info, err := o.SetupInfo()
	if err != nil || !info.Open || !info.Box.Equal(headPub) {
		t.Fatalf("setup info %+v %v", info, err)
	}
	if err := o.Setup(kernel.SignSetup(info.Box, key.Ed25519Signer(ownerPriv), key.Ed25519Signer(sparePriv))); err != nil {
		t.Fatal(err)
	}
	if err := o.Stop(); err != nil {
		t.Fatalf("STOP after setup: %v", err)
	}
	if err := m.ReadPool(0, "codex", 1, 2); errors.Is(err, ErrSetupOnly) {
		t.Fatalf("the meter after setup: %v", err)
	}
}

// TestOwnerReadsTheAnchors: the owner side reads the hardware keys setup
// logged, in order, and nothing before setup (#2779a's a0).
func TestOwnerReadsTheAnchors(t *testing.T) {
	o, _ := setupOnly(t)
	if a, err := o.Anchors(); !errors.Is(err, ErrSetupOnly) || a != nil {
		t.Fatalf("anchors before setup: %v %v, want ErrSetupOnly", a, err)
	}
	info, err := o.SetupInfo()
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Setup(kernel.SignSetup(info.Box, key.Ed25519Signer(ownerPriv), key.Ed25519Signer(sparePriv))); err != nil {
		t.Fatal(err)
	}
	a, err := o.Anchors()
	want := []key.PublicKey{key.Ed25519(ownerPub), key.Ed25519(sparePub)}
	if err != nil || !slices.Equal(a, want) {
		t.Fatalf("anchors after setup: %v %v, want %v", a, err, want)
	}
}
