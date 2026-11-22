package main

// REQ: RES-2, RES-3

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"testing"
)

// withPins sets modelPins for one test.
func withPins(t *testing.T, pins string) {
	saved := modelPins
	t.Cleanup(func() { modelPins = saved })
	modelPins = pins
}

// TestUnpinnedFileRefusedBeforeOpen (MUT-kill-6409-vision, #6457): a file
// with no pin is refused as not pinned, even when it is absent, so a
// missing unpinned file never reads as a missing model.
func TestUnpinnedFileRefusedBeforeOpen(t *testing.T) {
	withPins(t, hashOf("x")+"  m.onnx  https://example.invalid/m\n")
	_, err := readPinned(t.TempDir(), "absent.onnx")
	if !errors.Is(err, ErrRefused) || errors.Is(err, ErrMissing) || !strings.Contains(err.Error(), "absent.onnx is not pinned") {
		t.Fatalf("an absent unpinned file: %v", err)
	}
}

// TestPinnedOpenAndReadErrorsPassThrough: an error opening a pinned file,
// other than its absence, and an error reading it are returned as they
// are, not read as a refused or missing file: here a directory that is a
// regular file (ENOTDIR) and /proc/self/mem, a regular file whose read at
// offset 0 fails (EIO).
func TestPinnedOpenAndReadErrorsPassThrough(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc/self/mem")
	}
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	withPins(t, hashOf("x")+"  m.onnx  https://example.invalid/m\n"+hashOf("x")+"  mem  https://example.invalid/mem\n")
	if _, err := readPinned(notDir, "m.onnx"); !errors.Is(err, syscall.ENOTDIR) || errors.Is(err, ErrRefused) || errors.Is(err, ErrMissing) {
		t.Errorf("open under a regular file: %v, want ENOTDIR as it is", err)
	}
	if _, err := readPinned("/proc/self", "mem"); !errors.Is(err, syscall.EIO) || errors.Is(err, ErrRefused) {
		t.Errorf("a read that fails: %v, want EIO as it is", err)
	}
}

// TestReadPinnedClosesTheFile: reading a pinned file, accepted or refused,
// leaves no descriptor open on it: no entry of /proc/self/fd links into
// its directory afterwards (collection is off, so no finalizer closes a
// leaked one). Other tests' descriptors, which run in parallel, are not
// counted.
func TestReadPinnedClosesTheFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "m.onnx"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(dir, "w.onnx"), []byte("y"), 0o644)
	withPins(t, hashOf("x")+"  m.onnx  https://example.invalid/m\n"+hashOf("x")+"  w.onnx  https://example.invalid/w\n")
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	if _, err := os.ReadDir("/proc/self/fd"); err != nil {
		t.Skip("no /proc/self/fd")
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := readPinned(dir, "m.onnx"); err != nil {
			t.Fatal(err)
		}
		if _, err := readPinned(dir, "w.onnx"); !errors.Is(err, ErrRefused) {
			t.Fatalf("a wrong hash: %v", err)
		}
	}
	es, _ := os.ReadDir("/proc/self/fd")
	for _, e := range es {
		if to, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name())); err == nil && strings.HasPrefix(to, real+string(filepath.Separator)) {
			t.Errorf("descriptor %s is left open on %s", e.Name(), to)
		}
	}
}
