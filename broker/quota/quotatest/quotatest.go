// Package quotatest gives tests a directory on a small ext4 file system
// mounted with project quotas. It needs root and mkfs.ext4; without them,
// or on a kernel without quota support, the test is skipped, unless
// AGENTOS_REQUIRE_QUOTA is set (CI's root job), when it fails.
package quotatest

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Dir returns the root of a fresh mb-MiB ext4 file system with project
// quotas on, unmounted when the test ends.
func Dir(t testing.TB, mb int64) string {
	t.Helper()
	skip := func(why string, args ...any) {
		t.Helper()
		if os.Getenv("AGENTOS_REQUIRE_QUOTA") != "" {
			t.Fatalf("project quotas required: "+why, args...)
		}
		t.Skipf("no project quotas here: "+why, args...)
	}
	if os.Getuid() != 0 {
		skip("not root")
	}
	base := t.TempDir()
	img, dir := filepath.Join(base, "fs.img"), filepath.Join(base, "mnt")
	f, err := os.Create(img)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(mb << 20); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if out, err := exec.Command("mkfs.ext4", "-q", "-F", "-O", "quota,project", img).CombinedOutput(); err != nil {
		skip("mkfs.ext4: %v: %s", err, out)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("mount", "-o", "loop,prjquota", img, dir).CombinedOutput(); err != nil {
		skip("mount: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command("umount", "-l", dir).Run() })
	return dir
}
