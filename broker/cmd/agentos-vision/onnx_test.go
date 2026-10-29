//go:build vision_onnx

package main

// REQ: RES-3

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/vision"
)

// noModelsCause is this build's answer with nothing in -models.
const noModelsCause = vision.Missing

// TestOnnxLoadNeedsPinnedFiles: without the pinned library the runtime
// reports the models missing, and a library whose hash is not the pin is
// refused before it is ever loaded (VIS-A27).
func TestOnnxLoadNeedsPinnedFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := newRuntime(dir, 1).Load(); !errors.Is(err, ErrMissing) {
		t.Fatalf("empty directory: %v, want ErrMissing", err)
	}
	if err := os.WriteFile(filepath.Join(dir, ortLibrary), []byte("not the pinned library"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := newRuntime(dir, 1).Load(); !errors.Is(err, ErrRefused) {
		t.Fatalf("library off its pin: %v, want ErrRefused", err)
	}
}

// TestOnnxModelNameValid: the name hello reports for this build's models
// is one the client takes (vision.ValidModelName), every model it loads
// is pinned, and the pins are what modelsHash is made from.
func TestOnnxModelNameValid(t *testing.T) {
	if !vision.ValidModelName(modelsName) || !vision.ValidHash(modelsHash) {
		t.Fatalf("model name %q or hash %q is not valid", modelsName, modelsHash)
	}
	for _, f := range []string{ortLibrary, detectorFile, yunetFile, sfaceFile, plateFile, readerFile, yamnetFile} {
		if pinFor(f) == "" {
			t.Errorf("%s is not pinned", f)
		}
	}
}
