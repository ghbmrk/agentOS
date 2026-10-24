package proc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// REQ: STO-2

// STO-2a-b: a log written under another key is refused, never trimmed to a
// fresh box. kernel.Open alone would trim a one-entry log as a torn frame.
func TestCheckLogKeyReadsTheKernelsFrames(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "log")
	if err := checkLogKey(logPath, [32]byte{7}); err != nil {
		t.Fatalf("no log yet: %v", err)
	}
	cfg := KernelConfig{Log: logPath, Anchor: &kernel.MemAnchor{}, Key: [32]byte{7}, Pub: headPub, Sign: headPriv, Anchors: anchors}
	h, err := OpenKernel(cfg, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.With(func(k *kernel.Kernel) error { return k.Stop(1000) }); err != nil {
		t.Fatal(err)
	}
	h.Close()
	if err := checkLogKey(logPath, [32]byte{7}); err != nil {
		t.Fatalf("right key: %v", err)
	}
	if err := checkLogKey(logPath, [32]byte{8}); !errors.Is(err, ErrLogKey) {
		t.Fatalf("wrong key: got %v, want ErrLogKey", err)
	}
	// The case the check exists for: kernel.Open reads the one entry under
	// another key as a torn frame and opens empty, when no anchor kept the
	// head.
	cfg.Key, cfg.Anchor = [32]byte{8}, &kernel.MemAnchor{}
	h, err = OpenKernel(cfg, 1000)
	if err != nil {
		t.Fatalf("kernel.Open no longer trims a final frame it cannot open (%v); checkLogKey may be redundant", err)
	}
	h.Close()
	// A crash inside the first append leaves a torn frame, which is a fresh
	// box: kernel.Open trims it.
	torn := filepath.Join(dir, "torn")
	if err := os.WriteFile(torn, []byte{0, 0, 1, 0, 1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkLogKey(torn, [32]byte{7}); err != nil {
		t.Fatalf("torn first frame: %v", err)
	}
}
