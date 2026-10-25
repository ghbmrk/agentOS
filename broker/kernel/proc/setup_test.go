package proc

// REQ: KEY-4

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// #2905 open point 2: a kernel process started with no anchors serves only
// the setup step, its box key and STATUS, on any socket, until setup logs
// the owner's hardware keys; then every call is served again.
func TestASetupOnlyKernelServesOnlySetup(t *testing.T) {
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
	o, m := Owner{conns["owner"]}, Meter{conns["meter"]}
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
