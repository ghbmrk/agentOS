//go:build !linux

package update

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openBeneath opens name beneath dir one component at a time, each with
// O_NOFOLLOW, so a link at any component is refused as openat2 refuses it
// on Linux. validTargetPath has already refused "..", "." and empty
// components. This path serves agentos-release on a maintainer's machine
// (#4918 item 2); a box runs Linux.
func openBeneath(dir, name string) (*os.File, error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	parts := strings.Split(name, "/")
	path := dir
	for i, part := range parts {
		path = filepath.Join(path, part)
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if err != nil {
			return nil, &os.PathError{Op: "openat", Path: path, Err: err}
		}
		fd = next
	}
	return regularFile(fd, path)
}
