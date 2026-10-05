package overlay

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

// REQ: REV-1, REV-4, RES-4

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("whiteouts, opaque markers and overlay mounts need root (CI integration job)")
	}
}

func write(t *testing.T, root, rel, s string) {
	t.Helper()
	p := filepath.Join(root, rel)
	must(t, os.MkdirAll(filepath.Dir(p), 0o755))
	must(t, os.WriteFile(p, []byte(s), 0o644))
}

// image builds a lower layer with a few paths.
func image(t *testing.T) string {
	l := t.TempDir()
	write(t, l, "etc/conf", "base")
	write(t, l, "etc/keep", "keep")
	write(t, l, "app/a", "a")
	write(t, l, "app/b", "b")
	must(t, os.Symlink("etc/conf", filepath.Join(l, "link")))
	return l
}

func TestREV1CopyKeepsContentModesAndLinks(t *testing.T) {
	src := t.TempDir()
	write(t, src, "x/y", "data")
	must(t, os.Chmod(filepath.Join(src, "x/y"), 0o4750))
	must(t, os.Symlink("../x/y", filepath.Join(src, "x/l")))
	dst := filepath.Join(t.TempDir(), "copy")
	must(t, Copy(src, dst))
	a, err := Scan(src)
	must(t, err)
	b, err := Scan(dst)
	must(t, err)
	if len(a) != len(b) {
		t.Fatalf("copy has %d paths, source %d", len(b), len(a))
	}
	for k, e := range a {
		if !e.Same(b[k]) {
			t.Errorf("%s differs: %+v vs %+v", k, e, b[k])
		}
	}
	// The copy is independent of the source.
	write(t, src, "x/y", "changed")
	if got, _ := os.ReadFile(filepath.Join(dst, "x/y")); string(got) != "data" {
		t.Fatal("snapshot changed when the live layer did")
	}
	if err := Copy(src, dst); err == nil {
		t.Fatal("Copy overwrote an existing snapshot")
	}
}

func TestREV4DiffWithoutWhiteouts(t *testing.T) {
	low := image(t)
	a := View{Lower: low, Upper: t.TempDir()}
	b := View{Lower: low, Upper: t.TempDir()}
	write(t, b.Upper, "etc/conf", "changed")
	write(t, b.Upper, "new/file", "n")
	ch, err := Diff(a, b)
	must(t, err)
	got := ops(ch)
	want := "added new, added new/file, modified etc/conf"
	if got != want {
		t.Fatalf("diff = %s, want %s", got, want)
	}
	if ch, _ := Diff(a, a); len(ch) != 0 {
		t.Fatalf("a view differs from itself: %v", ch)
	}
}

func ops(ch []Change) string {
	var s []string
	for _, c := range ch {
		s = append(s, c.Op()+" "+c.Path)
	}
	sort.Strings(s)
	return strings.Join(s, ", ")
}

// guestView reads a directory tree the way the guest would see it.
func guestView(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || p == root {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case fi.IsDir():
			out[rel] = "dir"
		case fi.Mode()&os.ModeSymlink != 0:
			t, _ := os.Readlink(p)
			out[rel] = "->" + t
		default:
			b, _ := os.ReadFile(p)
			out[rel] = string(b)
		}
		return nil
	})
	must(t, err)
	return out
}

func viewMap(t *testing.T, v View) map[string]string {
	t.Helper()
	out := map[string]string{}
	paths := map[string]bool{}
	for _, root := range []string{v.Lower, v.Upper} {
		ents, err := Scan(root)
		must(t, err)
		for k := range ents {
			paths[k] = true
		}
	}
	for p := range paths {
		e, from, err := v.Lookup(p)
		must(t, err)
		switch e.Kind {
		case Absent:
		case Dir:
			out[p] = "dir"
		case Symlink:
			out[p] = "->" + e.Target
		default:
			b, _ := os.ReadFile(filepath.Join(from, p))
			out[p] = string(b)
		}
	}
	return out
}

func mount(t *testing.T, v View) string {
	t.Helper()
	work, merged := t.TempDir(), t.TempDir()
	must(t, syscall.Mount("overlay", merged, "overlay", syscall.MS_NOSUID|syscall.MS_NODEV,
		MountOptions(v.Lower, v.Upper, work)))
	t.Cleanup(func() { syscall.Unmount(merged, 0) })
	return merged
}

func sameMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestREV4ViewMatchesKernelOverlay makes the kernel produce whiteouts and
// opaque directories, then checks that View, Diff and Put agree with what a
// guest sees through a real overlay mount.
func TestREV4ViewMatchesKernelOverlay(t *testing.T) {
	needRoot(t)
	low := image(t)
	v := View{Lower: low, Upper: t.TempDir()}
	m := mount(t, v)
	must(t, os.Remove(filepath.Join(m, "etc/keep")))       // whiteout
	must(t, os.RemoveAll(filepath.Join(m, "app")))         // whiteout of a dir
	must(t, os.Mkdir(filepath.Join(m, "app"), 0o755))      // recreated: opaque
	write(t, m, "app/c", "c")                              // new file in opaque dir
	write(t, m, "etc/conf", "guest")                       // copy-up
	must(t, os.Remove(filepath.Join(m, "link")))           // whiteout of a symlink
	must(t, os.Symlink("app/c", filepath.Join(m, "link"))) // new symlink
	kernel := guestView(t, m)
	must(t, syscall.Unmount(m, 0))

	if got := viewMap(t, v); !sameMaps(got, kernel) {
		t.Fatalf("View disagrees with the kernel:\nview   %v\nkernel %v", got, kernel)
	}

	// Snapshot round trip: a copied layer mounts to the same view.
	snap := filepath.Join(t.TempDir(), "s")
	must(t, Copy(v.Upper, snap))
	if got := guestView(t, mount(t, View{Lower: low, Upper: snap})); !sameMaps(got, kernel) {
		t.Fatalf("snapshot mounts differently:\nsnap   %v\nkernel %v", got, kernel)
	}

	// Diff from the pristine image names exactly the guest's changes.
	empty := View{Lower: low, Upper: t.TempDir()}
	ch, err := Diff(empty, v)
	must(t, err)
	want := "added app/c, modified etc/conf, modified link, removed app/a, removed app/b, removed etc/keep"
	if got := ops(ch); got != want {
		t.Fatalf("diff = %s\nwant   %s", got, want)
	}

	// Put every change into a fresh layer: it then mounts to the same view.
	dst := View{Lower: low, Upper: t.TempDir()}
	for _, c := range ch {
		must(t, Put(dst, v, c.Path))
	}
	if got := guestView(t, mount(t, dst)); !sameMaps(got, kernel) {
		t.Fatalf("Put result mounts differently:\nput    %v\nkernel %v", got, kernel)
	}
	if ch, _ := Diff(dst, v); len(ch) != 0 {
		t.Fatalf("after Put, views still differ: %s", ops(ch))
	}
}

func TestREV1CopyKeepsWhiteoutsAndOpaqueMarkers(t *testing.T) {
	needRoot(t)
	src := t.TempDir()
	must(t, syscall.Mknod(filepath.Join(src, "gone"), syscall.S_IFCHR, 0))
	must(t, os.Mkdir(filepath.Join(src, "d"), 0o755))
	must(t, syscall.Setxattr(filepath.Join(src, "d"), opaqueXattr, []byte("y"), 0))
	dst := filepath.Join(t.TempDir(), "c")
	must(t, Copy(src, dst))
	e, err := Stat(dst, "gone")
	must(t, err)
	if e.Kind != Whiteout {
		t.Errorf("whiteout copied as %v", e.Kind)
	}
	e, err = Stat(dst, "d")
	must(t, err)
	if !e.Opaque {
		t.Error("opaque marker lost")
	}
	var buf [1]byte
	if n, _ := syscall.Getxattr(filepath.Join(dst, "d"), opaqueXattr, buf[:]); n != 1 || !bytes.Equal(buf[:], []byte("y")) {
		t.Error("opaque xattr not copied")
	}
}

// An image symlink to an absolute host path (Debian's /var/run -> /run)
// must never lead a layer operation into the host.
func TestREV1ImageSymlinksNeverReachTheHost(t *testing.T) {
	host := t.TempDir()
	write(t, host, "secret", "CANARY-HOST-FILE")
	low := image(t)
	must(t, os.MkdirAll(filepath.Join(low, "var"), 0o755))
	must(t, os.Symlink(host, filepath.Join(low, "var/run")))
	fork := View{Lower: low, Upper: t.TempDir()}
	must(t, os.MkdirAll(filepath.Join(fork.Upper, "var/run"), 0o755)) // guest replaced the link with a dir
	write(t, fork.Upper, "var/run/mine", "ok")

	for _, rel := range []string{"var/run/secret", "etc/conf/x"} {
		e, err := Stat(low, rel)
		must(t, err)
		if e.Kind != Absent {
			t.Errorf("Stat(image, %s) = %v, want absent", rel, e.Kind)
		}
	}
	if e, _, _ := fork.Lookup("var/run/secret"); e.Kind != Absent {
		t.Fatal("view shows a host file through an image symlink")
	}
	base := View{Lower: low, Upper: t.TempDir()}
	ch, err := Diff(base, fork)
	must(t, err)
	for _, c := range ch {
		if strings.Contains(c.Path, "secret") {
			t.Fatalf("diff reached the host: %v", ops(ch))
		}
	}
	if os.Geteuid() == 0 { // replacing the link with a dir sets an opaque marker
		dst := View{Lower: low, Upper: t.TempDir()}
		for _, c := range ch {
			must(t, Put(dst, fork, c.Path))
		}
		must(t, Put(dst, fork, "var/run/secret"))
		if _, err := os.Stat(filepath.Join(dst.Upper, "var/run/secret")); !os.IsNotExist(err) {
			t.Fatal("Put copied a host file into a guest layer")
		}
	}
	if _, err := Stat(low, "../etc"); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("dot-dot path: %v", err)
	}
}

func TestREV1SnapshotsCostWhatTheLayerCosts(t *testing.T) {
	src := t.TempDir()
	f, err := os.Create(filepath.Join(src, "sparse"))
	must(t, err)
	must(t, f.Truncate(1<<30)) // 1 GiB apparent, nothing allocated
	f.WriteAt([]byte("tail"), 1<<29)
	f.Close()
	write(t, src, "a", "linked")
	for i := 0; i < 20; i++ {
		must(t, os.Link(filepath.Join(src, "a"), filepath.Join(src, fmt.Sprintf("l%d", i))))
	}
	before, err := Measure(src)
	must(t, err)
	if before.Bytes > 1<<20 || before.Inodes != 3 { // root, sparse, and one inode for 21 links
		t.Fatalf("source usage %+v", before)
	}
	dst := filepath.Join(t.TempDir(), "c")
	must(t, Copy(src, dst))
	after, err := Measure(dst)
	must(t, err)
	if after.Bytes > 1<<20 || after.Inodes != before.Inodes {
		t.Fatalf("copy usage %+v, source %+v: sparse files or hardlinks were expanded", after, before)
	}
	a, _ := os.Stat(filepath.Join(dst, "a"))
	l, _ := os.Stat(filepath.Join(dst, "l7"))
	if !os.SameFile(a, l) {
		t.Fatal("hardlinks not kept")
	}
	ea, _ := Stat(src, "sparse")
	eb, _ := Stat(dst, "sparse")
	if !ea.Same(eb) {
		t.Fatal("sparse copy differs")
	}
}

func TestREV4OwnershipAndCapabilitiesCountAsChanges(t *testing.T) {
	needRoot(t)
	low := image(t)
	a := View{Lower: low, Upper: t.TempDir()}
	b := View{Lower: low, Upper: t.TempDir()}
	must(t, Copy(filepath.Join(low, "etc"), filepath.Join(b.Upper, "etc")))
	must(t, os.Lchown(filepath.Join(b.Upper, "etc/conf"), 1000, 1000))
	ch, err := Diff(a, b)
	must(t, err)
	if got := ops(ch); got != "modified etc/conf" {
		t.Fatalf("chown diff = %q", got)
	}
}

func TestREV1CopyRefusesDevicesAndDropsOverlayPointers(t *testing.T) {
	needRoot(t)
	src := t.TempDir()
	must(t, syscall.Mknod(filepath.Join(src, "sda"), syscall.S_IFBLK|0o600, 8<<8))
	err := Copy(src, filepath.Join(t.TempDir(), "c"))
	if !errors.Is(err, ErrUnsafe) || !strings.Contains(err.Error(), "sda") {
		t.Fatalf("block device copied: %v", err)
	}
	src = t.TempDir()
	must(t, syscall.Mknod(filepath.Join(src, "mem"), syscall.S_IFCHR|0o600, 1<<8|1))
	if err := Copy(src, filepath.Join(t.TempDir(), "c")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("/dev/mem copied: %v", err)
	}
	src = t.TempDir()
	must(t, os.Mkdir(filepath.Join(src, "d"), 0o755))
	must(t, syscall.Setxattr(filepath.Join(src, "d"), "trusted.overlay.redirect", []byte("/etc"), 0))
	must(t, syscall.Setxattr(filepath.Join(src, "d"), opaqueXattr, []byte("x"), 0))
	dst := filepath.Join(t.TempDir(), "c")
	must(t, Copy(src, dst))
	for _, n := range []string{"trusted.overlay.redirect", opaqueXattr} {
		if _, ok := getXattr(filepath.Join(dst, "d"), n); ok {
			t.Errorf("%s survived the copy", n)
		}
	}
}

// The kernel agrees: an upper directory over an image symlink hides it.
func TestREV1KernelHidesImageSymlinkUnderUpperDir(t *testing.T) {
	needRoot(t)
	host := t.TempDir()
	write(t, host, "secret", "CANARY-HOST-FILE")
	low := image(t)
	must(t, os.MkdirAll(filepath.Join(low, "var"), 0o755))
	must(t, os.Symlink(host, filepath.Join(low, "var/run")))
	v := View{Lower: low, Upper: t.TempDir()}
	must(t, os.MkdirAll(filepath.Join(v.Upper, "var/run"), 0o755))
	kernel := guestView(t, mount(t, v))
	if _, ok := kernel["var/run/secret"]; ok {
		t.Fatal("kernel shows the host file")
	}
	if got := viewMap(t, v); !sameMaps(got, kernel) {
		t.Fatalf("view %v\nkernel %v", got, kernel)
	}
}

// REV-4: merging a directory brings its owner, mode and guest xattrs, both
// for a directory the fork added and for one it only changed.
func TestREV4PutCarriesDirectoryOwnerAndXattrs(t *testing.T) {
	needRoot(t)
	low := image(t)
	base := View{Lower: low, Upper: t.TempDir()}
	fork := View{Lower: low, Upper: t.TempDir()}
	dst := View{Lower: low, Upper: t.TempDir()}
	proj := filepath.Join(fork.Upper, "proj")
	must(t, os.Mkdir(proj, 0o750))
	must(t, os.Lchown(proj, 1000, 1000))
	must(t, syscall.Setxattr(proj, "user.tag", []byte("fork"), 0))
	write(t, fork.Upper, "proj/f", "x")
	must(t, os.Lchown(filepath.Join(proj, "f"), 1000, 1000))
	etc := filepath.Join(fork.Upper, "etc")
	must(t, os.Mkdir(etc, 0o755))
	must(t, os.Lchown(etc, 1000, 1000))
	must(t, syscall.Setxattr(etc, "user.tag", []byte("fork"), 0))
	// dst's copy of etc carries an xattr the fork's does not.
	must(t, os.Mkdir(filepath.Join(dst.Upper, "etc"), 0o755))
	must(t, syscall.Setxattr(filepath.Join(dst.Upper, "etc"), "user.old", []byte("1"), 0))

	ch, err := Diff(base, fork)
	must(t, err)
	for _, c := range ch {
		must(t, Put(dst, fork, c.Path))
	}
	left, err := Diff(dst, fork)
	must(t, err)
	if len(left) != 0 {
		t.Fatalf("after Put, dst still differs from the fork: %s", ops(left))
	}
}

// Measure runs on a live worker's layer: files removed while it walks
// are skipped, not an error (L3 MUST-3 on #150).
func TestMeasureSkipsFilesThatVanish(t *testing.T) {
	root := t.TempDir()
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			d := filepath.Join(root, fmt.Sprintf("d%d", i%8))
			os.MkdirAll(d, 0o755)
			p := filepath.Join(d, fmt.Sprintf("f%d", i%64))
			os.WriteFile(p, []byte("x"), 0o644)
			os.Remove(p)
			if i%16 == 0 {
				os.RemoveAll(d)
			}
		}
	}()
	for range 300 {
		if _, err := Measure(root); err != nil {
			close(stop)
			<-done
			t.Fatalf("measure under churn: %v", err)
		}
	}
	close(stop)
	<-done
	if _, err := Measure(filepath.Join(root, "missing")); err == nil || strings.Contains(err.Error(), root) {
		t.Fatalf("measure of a missing layer: %v", err)
	}
}

// chain makes a directory chain depth levels deep under root, each level
// named name, through directory handles, so it can pass the host's path
// limit (PATH_MAX), and returns the bytes and inodes it allocated.
func chain(t *testing.T, root, name string, depth int) Usage {
	t.Helper()
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var u Usage
	for i := 0; i < depth; i++ {
		if err := syscall.Mkdirat(fd, name, 0o755); err != nil {
			t.Fatalf("level %d: %v", i, err)
		}
		next, err := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		syscall.Close(fd)
		if err != nil {
			t.Fatalf("level %d: %v", i, err)
		}
		fd = next
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			t.Fatal(err)
		}
		u.Bytes += st.Blocks * 512
		u.Inodes++
	}
	syscall.Close(fd)
	return u
}

// R4 on #166: a layer nested past the host's path limit is measured, not
// failed, so a deep worker can still be counted and cleaned.
func TestMeasureCountsALayerPastThePathLimit(t *testing.T) {
	root := t.TempDir()
	name := strings.Repeat("d", 40)
	want := chain(t, root, name, 200) // about 8,200 bytes of path
	var st syscall.Stat_t
	if err := syscall.Lstat(root, &st); err != nil {
		t.Fatal(err)
	}
	want.Bytes += st.Blocks * 512
	want.Inodes++
	got, err := Measure(root)
	if err != nil {
		t.Fatalf("measure past PATH_MAX: %v", err)
	}
	if got != want {
		t.Fatalf("measured %+v, want %+v", got, want)
	}
}

// A layer nested deeper than MaxTreeDepth is reported as too deep, a refusal
// callers treat as over the cap, never as no use; fds stay bounded.
func TestMeasureRefusesALayerDeeperThanTheCap(t *testing.T) {
	root := t.TempDir()
	chain(t, root, "a", MaxTreeDepth)
	if _, err := Measure(root); err != nil {
		t.Fatalf("measure at the cap: %v", err)
	}
	root = t.TempDir()
	chain(t, root, "a", MaxTreeDepth+1)
	if _, err := Measure(root); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("measure past the cap: %v", err)
	}
}

// Measure never follows a symlink, to a directory or out of the layer.
func TestMeasureDoesNotFollowSymlinks(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "big"), make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "out")); err != nil {
		t.Fatal(err)
	}
	u, err := Measure(root)
	if err != nil {
		t.Fatal(err)
	}
	if u.Inodes != 2 || u.Bytes >= 1<<20 {
		t.Fatalf("followed a symlink: %+v", u)
	}
}

// A layer is a directory: a root that is a file or a symlink, even to a
// directory, is an error, not a one-inode layer (security N1 on #174).
func TestMeasureRefusesARootThatIsNotADirectory(t *testing.T) {
	dir := t.TempDir()
	f, l := filepath.Join(dir, "f"), filepath.Join(dir, "l")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, l); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{f, l} {
		if _, err := Measure(p); !errors.Is(err, syscall.ENOTDIR) || strings.Contains(err.Error(), dir) {
			t.Fatalf("measure of %s: %v", filepath.Base(p), err)
		}
	}
}
