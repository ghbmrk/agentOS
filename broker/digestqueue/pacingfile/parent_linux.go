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
func openLeaseParent(path string) (*os.File, error) {
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
		fd = next
	}
	return os.NewFile(uintptr(fd), "accounting parent"), nil
}
