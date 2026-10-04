package overlay

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
)

// REQ: REV-1, REV-4

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
	must(t, syscall.Mount("overlay", merged, "overlay", 0,
		"lowerdir="+v.Lower+",upperdir="+v.Upper+",workdir="+work))
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
