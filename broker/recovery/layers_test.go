package recovery

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// REQ: REC-1

// Machine layers come back as the guest left them: whiteouts, the opaque
// marker, owners, and setuid bits (vm/overlay V17). Needs root, as the box
// and the CI machines job run it.
func TestRestoreKeepsMachineLayerWhiteoutsOpaqueMarkersAndOwners(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("whiteouts, opaque markers and owners need root (CI machines job)")
	}
	x := newBox(t)
	up := filepath.Join(x.dir, "broker", "machines", "m1", "upper")
	must(t, syscall.Mknod(filepath.Join(up, "deleted"), syscall.S_IFCHR, 0))
	od := filepath.Join(up, "opaque")
	must(t, os.Mkdir(od, 0o755))
	must(t, syscall.Setxattr(od, opaqueXattr, []byte("y"), 0))
	suid := filepath.Join(up, "su")
	must(t, os.WriteFile(suid, []byte("bin"), 0o755))
	must(t, os.Chown(suid, 1000, 1000))
	must(t, os.Chmod(suid, 0o755|os.ModeSetuid))

	var buf bytes.Buffer
	must(t, Backup(x.b, x.roots(), &buf, t0))
	dst := filepath.Join(t.TempDir(), "n")
	_, err := Restore(&buf, x.rk, dst, lay, Options{KeepOwners: true}, t0)
	must(t, err)
	nu := filepath.Join(dst, "broker", "machines", "m1", "upper")
	var st syscall.Stat_t
	must(t, syscall.Lstat(filepath.Join(nu, "deleted"), &st))
	if st.Mode&syscall.S_IFMT != syscall.S_IFCHR || st.Rdev != 0 {
		t.Fatal("whiteout not restored")
	}
	var v [1]byte
	if n, err := syscall.Getxattr(filepath.Join(nu, "opaque"), opaqueXattr, v[:]); err != nil || n != 1 || v[0] != 'y' {
		t.Fatalf("opaque marker: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(nu, "su"))
	must(t, err)
	s := fi.Sys().(*syscall.Stat_t)
	if s.Uid != 1000 || s.Gid != 1000 || fi.Mode()&os.ModeSetuid == 0 {
		t.Fatalf("owner %d:%d mode %v", s.Uid, s.Gid, fi.Mode())
	}
	sameTree(t, filepath.Join(x.dir, "broker"), filepath.Join(dst, "broker"))
}
