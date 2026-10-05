package overlay

// REQ: CAP-8, RES-4

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type delRig struct {
	t            *testing.T
	upper, lower string
}

func newDelRig(t *testing.T) *delRig {
	d := t.TempDir()
	r := &delRig{t, filepath.Join(d, "upper"), filepath.Join(d, "lower")}
	for _, p := range []string{r.upper, r.lower} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func (r *delRig) file(root, rel, content string) {
	r.t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *delRig) del(recursive bool, max int, paths ...string) DeleteResult {
	r.t.Helper()
	out, err := Delete(r.upper, r.lower, paths, recursive, max)
	if err != nil {
		r.t.Fatal(err)
	}
	return out
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func TestDeleteRemovesFromTheUpperLayerOnly(t *testing.T) {
	r := newDelRig(t)
	r.file(r.upper, "big", strings.Repeat("x", 64<<10))
	r.file(r.upper, "etc/conf", "mine")
	r.file(r.lower, "etc/conf", "base")
	r.file(r.lower, "usr/bin/tool", "base")
	out := r.del(false, 100, "/big", "/etc/conf", "/usr/bin/tool", "/nope", "relative", "/a/../b", "/", "/a//b")
	want := []string{Removed, RemovedBase, BaseImage, NotFound, BadPath, BadPath, BadPath, BadPath}
	if fmt.Sprint(out.Codes) != fmt.Sprint(want) {
		t.Fatalf("codes = %v, want %v", out.Codes, want)
	}
	if out.Files != 2 || out.Bytes < 64<<10 || out.More {
		t.Fatalf("counts = %+v", out)
	}
	if exists(filepath.Join(r.upper, "big")) || !exists(filepath.Join(r.lower, "etc/conf")) || !exists(filepath.Join(r.lower, "usr/bin/tool")) {
		t.Fatal("deleted the wrong layer")
	}
}

// R-DEL7: a symlink in the upper layer is removed itself, whatever it
// points at, and a symlinked parent is refused; no target is touched.
func TestDeleteNeverFollowsASymlink(t *testing.T) {
	r := newDelRig(t)
	host := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(host, []byte("canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.file(r.upper, "keep/f", "x")
	for name, target := range map[string]string{"to-host": host, "to-up": "..", "to-dir": filepath.Dir(host)} {
		if err := os.Symlink(target, filepath.Join(r.upper, name)); err != nil {
			t.Fatal(err)
		}
	}
	out := r.del(true, 100, "/to-host", "/to-up", "/to-dir/host-secret", "/to-dir")
	if fmt.Sprint(out.Codes) != fmt.Sprint([]string{Removed, Removed, SymlinkInPath, Removed}) {
		t.Fatalf("codes = %v", out.Codes)
	}
	if b, err := os.ReadFile(host); err != nil || string(b) != "canary" {
		t.Fatal("a symlink's target was touched")
	}
	if !exists(filepath.Join(r.upper, "keep/f")) || !exists(r.upper) {
		t.Fatal("removing a link to .. removed what it points at")
	}
}

// A directory needs recursive; whiteouts and directories inside go with
// it, and nothing is created in the upper layer.
func TestDeleteDirectories(t *testing.T) {
	r := newDelRig(t)
	r.file(r.upper, "d/a", "1")
	r.file(r.upper, "d/sub/b", "2")
	if err := os.Mkdir(filepath.Join(r.upper, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mknod(filepath.Join(r.upper, "d", "gone"), syscall.S_IFCHR, 0); err != nil {
		t.Skipf("no whiteouts here (mknod: %v)", err)
	}
	out := r.del(false, 100, "/d", "/empty", "/d/gone")
	if fmt.Sprint(out.Codes) != fmt.Sprint([]string{NotEmpty, Removed, NotFound}) {
		t.Fatalf("codes = %v", out.Codes)
	}
	out = r.del(true, 100, "/d")
	if out.Codes[0] != Removed || out.Files != 5 {
		t.Fatalf("recursive = %+v, want 5 entries (a, b, sub, gone, d)", out)
	}
	ents, _ := os.ReadDir(r.upper)
	if len(ents) != 0 {
		t.Fatalf("upper holds %v", ents)
	}
}

// R-DEL7: the entry budget stops a walk part way; asking again continues.
func TestDeleteEntryBudget(t *testing.T) {
	r := newDelRig(t)
	for i := range 10 {
		r.file(r.upper, fmt.Sprintf("d/f%d", i), "x")
	}
	r.file(r.upper, "later", "x")
	out := r.del(true, 4, "/d", "/later")
	if fmt.Sprint(out.Codes) != fmt.Sprint([]string{MoreRemains, MoreRemains}) || !out.More || out.Files != 4 {
		t.Fatalf("first pass = %+v", out)
	}
	out = r.del(true, 100, "/d", "/later")
	if fmt.Sprint(out.Codes) != fmt.Sprint([]string{Removed, Removed}) || out.Files != 8 {
		t.Fatalf("second pass = %+v", out)
	}
}

// Removing an opaque upper directory brings the base directory back.
func TestDeleteOpaqueDirectorySaysTheBaseIsBack(t *testing.T) {
	r := newDelRig(t)
	r.file(r.lower, "srv/x", "base")
	r.file(r.upper, "srv/y", "mine")
	if err := syscall.Setxattr(filepath.Join(r.upper, "srv"), opaqueXattr, []byte("y"), 0); err != nil {
		t.Skipf("trusted xattrs need root: %v", err)
	}
	if out := r.del(false, 100, "/srv/x"); out.Codes[0] != NotFound {
		t.Fatalf("a path hidden by an opaque directory = %v", out.Codes)
	}
	if out := r.del(true, 100, "/srv"); out.Codes[0] != RemovedBase {
		t.Fatalf("removing the opaque directory = %v", out.Codes)
	}
}

// R-DEL7: a mount point inside the upper layer is refused, and so is any
// path through it (NO_XDEV).
func TestDeleteRefusesAMountPoint(t *testing.T) {
	r := newDelRig(t)
	mnt := filepath.Join(r.upper, "mnt")
	r.file(r.upper, "mnt/.keep", "")
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, "size=1m"); err != nil {
		t.Skipf("mounting needs root: %v", err)
	}
	defer syscall.Unmount(mnt, syscall.MNT_DETACH)
	if err := os.WriteFile(filepath.Join(mnt, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A file bind-mounted inside a directory being removed.
	host := filepath.Join(t.TempDir(), "host-file")
	if err := os.WriteFile(host, []byte("canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.file(r.upper, "outer/x", "x")
	r.file(r.upper, "outer/bound", "")
	bound := filepath.Join(r.upper, "outer", "bound")
	if err := syscall.Mount(host, bound, "", syscall.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer syscall.Unmount(bound, syscall.MNT_DETACH)
	// A host directory bind-mounted from the same file system: its device
	// number matches, so only the mount table tells (NO_XDEV).
	hostDir := filepath.Join(t.TempDir(), "host dir")
	if err := os.MkdirAll(hostDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "f"), []byte("canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.file(r.upper, "sp ace/.keep", "")
	spaced := filepath.Join(r.upper, "sp ace")
	if err := syscall.Mount(hostDir, spaced, "", syscall.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	defer syscall.Unmount(spaced, syscall.MNT_DETACH)
	out := r.del(false, 100, "/mnt", "/mnt/f", "/mnt/missing", "/outer/bound", "/sp ace/f")
	if fmt.Sprint(out.Codes) != fmt.Sprint([]string{MountPoint, MountPoint, MountPoint, MountPoint, MountPoint}) {
		t.Fatalf("codes = %v", out.Codes)
	}
	out = r.del(true, 100, "/mnt", "/outer", "/sp ace")
	if fmt.Sprint(out.Codes) != fmt.Sprint([]string{MountPoint, MountPoint, MountPoint}) {
		t.Fatalf("recursive codes = %v", out.Codes)
	}
	for _, p := range []string{host, filepath.Join(hostDir, "f"), filepath.Join(mnt, "f")} {
		if !exists(p) {
			t.Fatalf("deleted %s across a mount", p)
		}
	}
}
