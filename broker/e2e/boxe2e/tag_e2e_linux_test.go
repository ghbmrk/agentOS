//go:build agentos_e2e

package main

import (
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"testing"
)

// REQ: HW-10

// checkVaultBuild reads the e2e tag from the vault process's build info.
// A tagged test binary carries it, and so does cmd/agentos-egress built
// with image.yml's flags: -tags survives -trimpath -ldflags=-buildid=.
func TestTaggedBuildsCarryE2ETag(t *testing.T) {
	own, ok := debug.ReadBuildInfo()
	if !ok || !hasTag(own, e2eTag) {
		t.Fatal("tagged test binary does not carry the e2e tag")
	}
	bin := filepath.Join(t.TempDir(), "agentos-egress")
	cmd := exec.Command("go", "build", "-tags", e2eTag, "-trimpath", "-ldflags=-buildid=", "-o", bin, "./cmd/agentos-egress")
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	bi, err := buildinfo.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	if !hasTag(bi, e2eTag) {
		t.Fatalf("image.yml's vault build has no %s tag in its build info", e2eTag)
	}
}
