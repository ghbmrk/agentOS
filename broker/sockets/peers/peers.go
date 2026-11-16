// Package peers is the peer rule on one Unix socket: a listener that admits
// only the uids it is given, and the uid on the other end of a connection
// (SO_PEERCRED). The kernel's process serves its sockets with it and links
// nothing else of the sockets package, whose JSON-line Server is agentosd's
// way in (#6039).
package peers

import (
	"errors"
	"net"
	"os"
)

// ListenUnix opens a unix socket at path that admits only the peer uids given;
// every other connection is closed unread. A stale socket file is replaced,
// and the file goes when the listener closes (net.Listen's own unix
// listener unlinks it). It serves listeners outside sockets.Server that
// speak HTTP or the kernel's frames (the key holders, the CH-4 checker,
// SIM-split) under the same peer rule.
func ListenUnix(path string, uids ...int) (net.Listener, error) {
	if len(uids) == 0 {
		return nil, errors.New("sockets: a socket needs at least one peer uid")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// The uid check, not the mode, admits the peer; the run directory
	// keeps the path unlistable.
	if err := os.Chmod(path, 0o666); err != nil {
		ln.Close()
		return nil, err
	}
	allow := map[int]bool{}
	for _, u := range uids {
		allow[u] = true
	}
	return listener{ln, allow}, nil
}

type listener struct {
	net.Listener
	allow map[int]bool
}

func (l listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if uid, ok := UID(c); ok && l.allow[uid] {
			return c, nil
		}
		c.Close()
	}
}
