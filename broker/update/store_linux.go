package update

import (
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// openBeneath opens name beneath dir with openat2: RESOLVE_BENEATH and
// RESOLVE_NO_SYMLINKS refuse a link at any component (#3989).
func openBeneath(dir, name string) (*os.File, error) {
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	path := filepath.Join(dir, filepath.FromSlash(name))
	how := unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	for tries := 0; ; tries++ {
		fd, err := unix.Openat2(int(d.Fd()), name, &how)
		if err == nil {
			return regularFile(fd, path)
		}
		// EAGAIN: a rename raced the walk; openat2 asks for a retry.
		if (err == unix.EAGAIN || err == unix.EINTR) && tries < 8 {
			continue
		}
		return nil, &os.PathError{Op: "openat2", Path: path, Err: err}
	}
}
