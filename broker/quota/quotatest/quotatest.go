// Package quotatest gives tests a directory on a small file system mounted
// with project quotas: ext4, or XFS where the kernel lacks ext4's quota
// format (quota_v2). It needs root and mkfs; without them, or on a kernel
// without quota support, the test is skipped, unless AGENTOS_REQUIRE_QUOTA
// is set (CI's root job), when it fails.
package quotatest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/childproc"
)

// Kinds are the file systems with project quotas Dir tries, in order.
var Kinds = []string{"ext4", "xfs"}

// Dir returns the root of a fresh file system of at least mb MiB with
// project quotas on, unmounted when the test ends: the first of Kinds
// that this host can mount.
func Dir(t testing.TB, mb int64) string {
	t.Helper()
	var why []error
	for _, k := range Kinds {
		d, err := On(t, k, mb)
		if err == nil {
			t.Logf("project quotas on %s", k)
			return d
		}
		why = append(why, err)
	}
	Unavailable(t, fmt.Sprint(why))
	return ""
}

// Unavailable skips the test, or fails it when AGENTOS_REQUIRE_QUOTA is set.
func Unavailable(t testing.TB, why string) {
	t.Helper()
	if os.Getenv("AGENTOS_REQUIRE_QUOTA") != "" {
		t.Fatalf("project quotas required: %s", why)
	}
	t.Skipf("no project quotas here: %s", why)
}

// On returns the root of a fresh kind ("ext4" or "xfs") file system of at
// least mb MiB with project quotas on, unmounted when the test ends, or why
// this host cannot make one.
func On(t testing.TB, kind string, mb int64) (string, error) {
	t.Helper()
	if os.Getuid() != 0 {
		return "", fmt.Errorf("%s: not root", kind)
	}
	var mkfs []string
	opts := "loop"
	switch kind {
	case "ext4":
		mkfs, opts = []string{"mkfs.ext4", "-q", "-F", "-O", "quota,project"}, opts+",prjquota"
	case "xfs":
		mb = max(mb, 320) // mkfs.xfs's smallest file system
		mkfs, opts = []string{"mkfs.xfs", "-q", "-f"}, opts+",prjquota"
	default:
		return "", fmt.Errorf("unknown file system %q", kind)
	}
	base := t.TempDir()
	img, dir := filepath.Join(base, "fs.img"), filepath.Join(base, "mnt")
	f, err := os.Create(img)
	if err != nil {
		return "", err
	}
	err = f.Truncate(mb << 20)
	f.Close()
	if err != nil {
		return "", err
	}
	if out, err := command(mkfs[0], append(mkfs[1:], img)...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("%s: %v: %s", mkfs[0], err, out)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	if out, err := command("mount", "-o", opts, img, dir).CombinedOutput(); err != nil {
		return "", fmt.Errorf("mount %s: %v: %s", kind, err, out)
	}
	t.Cleanup(func() { command("umount", "-l", dir).Run() })
	return dir, nil
}

// toolPath is all of mkfs's, mount's and umount's environment
// (P3-4b-3r-env-r8b): they find their helpers there and need nothing else.
const toolPath = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"

func command(name string, args ...string) *childproc.Cmd {
	return childproc.Command(context.Background(), childproc.NewEnv(toolPath), childproc.Options{}, name, args...)
}
