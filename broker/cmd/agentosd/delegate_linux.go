//go:build linux

package main

import "syscall"

// delegateMarked reports whether systemd marked the group as delegated:
// it sets trusted.delegate (and, from v251, user.delegate) on a unit's
// group when the unit has Delegate=yes.
func delegateMarked(path string) bool {
	buf := make([]byte, 8)
	for _, name := range []string{"trusted.delegate", "user.delegate"} {
		if n, err := syscall.Getxattr(path, name, buf); err == nil && n > 0 && buf[0] == '1' {
			return true
		}
	}
	return false
}
