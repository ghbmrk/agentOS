//go:build linux

package pacingfile

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	maxLeasePathBytes        = 4095
	maxLeaseParentComponents = 64
)

// openLeaseParent rejects invalid/over-bound paths before opening anything, then
// resolves each parent component through its predecessor's held descriptor. It
// never follows an intermediate symlink. Only current and next traversal fds
// coexist; callers own the final fd. This is not atomic whole-path custody,
// permission/ownership qualification of ancestors, or a filesystem I/O deadline.
func openLeaseParent(path string) (*os.File, error) { return openLeaseParentProtected(path, nil) }

func protectedAncestor(st *syscall.Stat_t, owners []uint32) bool {
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR || st.Mode&0022 != 0 {
		return false
	}
	for _, uid := range owners {
		if st.Uid == uid {
			return true
		}
	}
	return false
}
func checkProtectedAncestor(fd int, owners []uint32) bool {
	if owners == nil {
		return true
	}
	var st syscall.Stat_t
	return syscall.Fstat(fd, &st) == nil && protectedAncestor(&st, owners)
}
func openLeaseParentProtected(path string, owners []uint32) (*os.File, error) {
	if len(path) > maxLeasePathBytes || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.HasSuffix(path, ".lock") || strings.HasSuffix(path, ".tmp") {
		return nil, ErrStorage
	}
	parent := strings.TrimPrefix(filepath.Dir(path), "/")
	var parts []string
	if parent != "" {
		parts = strings.Split(parent, "/")
	}
	if len(parts) > maxLeaseParentComponents {
		return nil, ErrStorage
	}
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
	fd, err := syscall.Open("/", flags, 0)
	if err != nil {
		return nil, ErrStorage
	}
	if !checkProtectedAncestor(fd, owners) {
		syscall.Close(fd)
		return nil, ErrStorage
	}
	for _, part := range parts {
		next, err := syscall.Openat(fd, part, flags, 0)
		closed := syscall.Close(fd)
		if err != nil {
			return nil, ErrStorage
		}
		if closed != nil {
			syscall.Close(next)
			return nil, ErrStorage
		}
		if !checkProtectedAncestor(next, owners) {
			syscall.Close(next)
			return nil, ErrStorage
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "accounting parent"), nil
}
