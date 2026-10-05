package overlay

// REQ: CAP-8, RES-4

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
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

// A recursive delete stops at MaxTreeDepth with too_deep, holding at most
// that many directory handles; deleting a deeper path first shortens the
// tree (L3 MUST-1 on #166).
func TestDeleteDepthIsBounded(t *testing.T) {
	r := newDelRig(t)
	deep := func(n int) string {
		p := "/c"
		for range n - 1 {
			p += "/c"
		}
		return p
	}
	if err := os.MkdirAll(filepath.Join(r.upper, deep(MaxTreeDepth+40)), 0o755); err != nil {
		t.Fatal(err)
	}
	if out := r.del(true, 100_000, "/c"); out.Codes[0] != TooDeep {
		t.Fatalf("a chain deeper than the bound = %+v", out)
	}
	if !exists(filepath.Join(r.upper, deep(MaxTreeDepth+40))) {
		t.Fatal("a refused walk removed part of the chain")
	}
	if out := r.del(true, 100_000, deep(41)); out.Codes[0] != Removed {
		t.Fatalf("the deeper part = %+v", out)
	}
	if out := r.del(true, 100_000, "/c"); out.Codes[0] != Removed || out.Files != 40 {
		t.Fatalf("the rest = %+v", out)
	}
}

// A path past the host's PATH_MAX under upper still resolves, handle by
// handle; an over-long name is bad_path; errors carry no broker
// directory (L3 S1 and SHOULD-1 on #166).
func TestDeleteNamesNoHostPath(t *testing.T) {
	r := newDelRig(t)
	name := strings.Repeat("n", 255)
	long := ""
	for len(long)+256 <= maxPathLen {
		long += "/" + name
	}
	r.file(r.upper, "f", "x")
	// Build the guest path's directories handle by handle: under the
	// broker's upper directory the host path passes the kernel's limit.
	fd, err := syscall.Open(r.upper, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(long[1:], "/")
	for _, c := range parts[:len(parts)-1] {
		if err := syscall.Mkdirat(fd, c, 0o755); err != nil {
			t.Fatal(err)
		}
		next, err := syscall.Openat(fd, c, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		syscall.Close(fd)
		if err != nil {
			t.Fatal(err)
		}
		fd = next
	}
	leaf, err := syscall.Openat(fd, parts[len(parts)-1], syscall.O_CREAT|syscall.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	syscall.Close(leaf)
	syscall.Close(fd)
	if len(r.upper)+len(long) <= maxPathLen {
		t.Fatal("the path is within the host's limit")
	}
	out := r.del(false, 100, long, "/"+strings.Repeat("n", 256), long+"x")
	if fmt.Sprint(out.Codes) != fmt.Sprint([]string{Removed, BadPath, BadPath}) {
		t.Fatalf("long paths = %v", out.Codes)
	}
	got, err := Delete(filepath.Join(r.upper, "missing"), r.lower, []string{"/f"}, false, 100)
	if err != ErrDeleteFailed || strings.Contains(err.Error(), "/") || got.Fault == nil {
		t.Fatalf("error = %v, fault = %v", err, got.Fault)
	}
}

// A failure part way answers delete_failed for that path alone: no host
// path, upper directory or errno reaches the guest; the cause is the
// Fault, for the broker's log (L3 S1 on #166).
func TestDeleteFailureSaysOnlyACode(t *testing.T) {
	r := newDelRig(t)
	r.file(r.upper, "bad", "x")
	r.file(r.upper, "ok", "x")
	defer func(f func(int, string) error) { unlinkat = f }(unlinkat)
	unlinkat = func(dir int, name string) error {
		if name == "bad" {
			return &os.PathError{Op: "unlinkat", Path: filepath.Join(r.upper, name), Err: syscall.EIO}
		}
		return syscall.Unlinkat(dir, name)
	}
	out, err := Delete(r.upper, r.lower, []string{"/bad", "/ok"}, false, 100)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(out.Codes) != fmt.Sprint([]string{DeleteFailed, Removed}) || out.Files != 1 {
		t.Fatalf("out = %+v", out)
	}
	if answer := fmt.Sprint(out.Codes, out.Files, out.Bytes, out.More); strings.Contains(answer, "/") || strings.Contains(answer, "input/output") {
		t.Fatalf("answer = %q", answer)
	}
	if out.Fault == nil || !strings.Contains(out.Fault.Error(), r.upper) {
		t.Fatalf("fault = %v", out.Fault)
	}
}

// A call runs out of time as it runs out of entries: what is left is
// more_remains, and asking again finishes (security on #166).
func TestDeleteTimeBudget(t *testing.T) {
	r := newDelRig(t)
	for i := range 50 {
		r.file(r.upper, fmt.Sprintf("d/f%d", i), "x")
	}
	r.file(r.upper, "e", "x")
	defer func(f func() time.Time) { clock = f }(clock)
	now := time.Unix(0, 0)
	clock = func() time.Time { now = now.Add(time.Second); return now } // each look costs a second
	out := r.del(true, 100_000, "/d", "/e")
	if fmt.Sprint(out.Codes) != fmt.Sprint([]string{MoreRemains, MoreRemains}) || !out.More || out.Files == 0 || out.Files >= 50 {
		t.Fatalf("out of time = %+v", out)
	}
	clock = time.Now
	if out := r.del(true, 100_000, "/d", "/e"); fmt.Sprint(out.Codes) != fmt.Sprint([]string{Removed, Removed}) {
		t.Fatalf("again = %+v", out)
	}
}

// A path 1,000 directories deep resolves in time linear in its depth,
// on the real clock, and repeated recursive deletes from the bottom up
// clear the chain, each removing something (L3 on #166).
func TestDeleteDeepPathsMakeProgress(t *testing.T) {
	r := newDelRig(t)
	const depth = 1000
	deep := strings.Repeat("/c", depth)
	if err := os.MkdirAll(filepath.Join(r.upper, deep), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if out := r.del(false, 100_000, deep); out.Codes[0] != Removed {
		t.Fatalf("the deepest directory = %+v", out)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("resolving %d levels took %v", depth, took)
	}
	defer func(d time.Duration) { deleteTimeout = d }(deleteTimeout)
	deleteTimeout = 0 // the time is always up: progress must still be made
	for n := depth - 1 - MaxTreeDepth + 1; ; n -= MaxTreeDepth {
		p := strings.Repeat("/c", max(n, 1))
		for {
			out := r.del(true, 100_000, p)
			if out.Files == 0 {
				t.Fatalf("no progress at depth %d: %+v", n, out)
			}
			if out.Codes[0] == Removed {
				break
			}
			if out.Codes[0] != MoreRemains {
				t.Fatalf("depth %d = %+v", n, out)
			}
		}
		if n <= 1 {
			break
		}
	}
}

// A 10,000-deep chain costs a delete only its bounded walk: under the
// depth bound in handles, and a small heap (security on #166).
func TestDeleteDeepChainStaysSmall(t *testing.T) {
	r := newDelRig(t)
	fd, err := syscall.Open(r.upper, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for range 10_000 {
		if err := syscall.Mkdirat(fd, "c", 0o755); err != nil {
			t.Fatal(err)
		}
		next, err := syscall.Openat(fd, "c", syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		syscall.Close(fd)
		if err != nil {
			t.Fatal(err)
		}
		fd = next
	}
	syscall.Close(fd)
	// Handles: what is open now, the walk's one per level, and headroom.
	open, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	tight := lim
	tight.Cur = uint64(len(open) + MaxTreeDepth + 16)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &tight); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim) }) // before TempDir's removal
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	out := r.del(true, 100_000, "/c")
	runtime.ReadMemStats(&after)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	if out.Codes[0] != TooDeep || out.Fault != nil {
		t.Fatalf("out = %+v", out)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 8<<20 {
		t.Fatalf("the walk allocated %d bytes", alloc)
	}
	if now, _ := os.ReadDir("/proc/self/fd"); len(now) > len(open) {
		t.Fatalf("handles leaked: %d then %d", len(open), len(now))
	}
}

// freed bytes count a file only when no other link keeps its blocks.
func TestDeleteFreedBytesSkipHardlinks(t *testing.T) {
	r := newDelRig(t)
	r.file(r.upper, "a", strings.Repeat("x", 64<<10))
	if err := os.Link(filepath.Join(r.upper, "a"), filepath.Join(r.upper, "b")); err != nil {
		t.Fatal(err)
	}
	if out := r.del(false, 100, "/a"); out.Files != 1 || out.Bytes != 0 {
		t.Fatalf("a linked file freed %d bytes", out.Bytes)
	}
	if out := r.del(false, 100, "/b"); out.Bytes < 64<<10 {
		t.Fatalf("the last link freed %d bytes", out.Bytes)
	}
}
