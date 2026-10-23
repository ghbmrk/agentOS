package run

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// REQ: STO-2, CLK-1

func testKeys() KernelKeys {
	return KernelKeys{Log: [32]byte{9}, Head: headPriv, Anchors: anchors}
}

// pipeWith is a pipe's read end holding b, its writer closed.
func pipeWith(t *testing.T, b []byte) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return r
}

// STO-2a-e: the kernel gets its keys from the unlock step's pipe, whole.
func TestTheHandoffCarriesTheKernelsKeys(t *testing.T) {
	b, err := testKeys().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ReadKeys(pipeWith(t, b))
	if err != nil {
		t.Fatal(err)
	}
	if k.Log != [32]byte{9} || !k.Head.Equal(headPriv) || len(k.Anchors) != 2 || !k.Anchors[0].Equal(ownerPub) || !k.Anchors[1].Equal(sparePub) {
		t.Fatalf("keys did not survive the hand-off: %+v", k)
	}
	k.Wipe()
	if k.Head != nil || k.Log != ([32]byte{}) {
		t.Fatal("Wipe left keys")
	}
}

// A hand-off that is short, long, of another version, or not on a pipe is
// refused whole: no key of it is used.
func TestADamagedHandoffIsRefused(t *testing.T) {
	good, err := testKeys().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	extra := append(bytes.Clone(good), 0)
	retag := bytes.Clone(good)
	retag[len(handoffTag)-2] = '2'
	miscount := bytes.Clone(good)
	miscount[len(handoffTag)+64] = 3
	for name, b := range map[string][]byte{
		"empty": nil, "short": good[:len(good)-1], "long": extra, "tag": retag, "count": miscount,
		"huge": bytes.Repeat([]byte{1}, maxHandoff+1),
	} {
		if _, err := ReadKeys(pipeWith(t, b)); !errors.Is(err, ErrHandoff) {
			t.Errorf("%s: got %v, want ErrHandoff", name, err)
		}
	}
	// A file on the drive never stands in for the unlock step.
	p := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(p, good, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeys(f); !errors.Is(err, ErrHandoff) {
		t.Fatalf("regular file: got %v, want ErrHandoff", err)
	}
}

// D-146: the owner's anchors are 1 to MaxAnchors distinct keys.
func TestAnchorsAreBounded(t *testing.T) {
	one := []byte(ownerPub)
	if a, err := ParseAnchors(one); err != nil || len(a) != 1 {
		t.Fatalf("one key: %v %v", a, err)
	}
	many := bytes.Repeat(make([]byte, ed25519.PublicKeySize), MaxAnchors+1)
	for i := 0; i <= MaxAnchors; i++ {
		many[i*ed25519.PublicKeySize] = byte(i)
	}
	for name, b := range map[string][]byte{
		"none": nil, "ragged": one[:31], "dup": append(bytes.Clone(one), one...), "many": many,
	} {
		if _, err := ParseAnchors(b); !errors.Is(err, ErrHandoff) {
			t.Errorf("%s: got %v, want ErrHandoff", name, err)
		}
	}
	if _, err := (KernelKeys{Head: headPriv}).Marshal(); !errors.Is(err, ErrHandoff) {
		t.Fatalf("no anchors: got %v", err)
	}
}

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
